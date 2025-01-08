mod vanity_gpg;

use vanity_gpg::{CipherSuite, VanitySecretKey};
use clap::Parser;
use std::{
    fs,
    io,
    io::Write,
    mem,
    path::Path,
    sync::mpsc::channel,
    thread,
    time::Instant,
};
use ocl::{Buffer, Device, Platform, ProQue};
use rand::thread_rng;
use pgp::types::PublicKeyTrait;
use log::{warn, info, debug};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Cipher suite of the vanity key
    /// ed25519, ecdsa-****, rsa**** => Primary key
    /// cv25519,  ecdh-****          => Subkey
    /// Use gpg CLI for further editing of the key.
    #[arg(short, long, default_value_t, value_enum, verbatim_doc_comment)]
    cipher_suite: vanity_gpg::CipherSuite,

    /// OpenPGP compatible user ID
    #[arg(short, long, default_value_t = String::from("Dummy <dummy@example.com>"), verbatim_doc_comment)]
    user_id: String,

    /// A pattern less than 40 chars for matching fingerprints
    /// Format:
    /// * 0-9A-F are fixed, G-Z are wildcards
    /// * Other chars will be ignored
    /// * Case insensitive
    /// Example:
    /// * 11XXXX** may output a fingerprint ends with 11222234 or 11AAAABF
    /// * 11XXYYZZ may output a fingerprint ends with 11223344 or 11AABBCC
    #[arg(short, long, verbatim_doc_comment)]
    pattern: Option<String>,

    /// OpenCL kernel function for uint h[5] for matching fingerprints
    /// Ignore the pattern and no estimate is given if this has been set
    /// Example:
    /// * (h[4] & 0xFFFF)     == 0x1234     outputs a fingerprint ends with 1234
    /// * (h[0] & 0xFFFF0000) == 0xABCD0000 outputs a fingerprint starts with ABCD
    #[arg(short, long, verbatim_doc_comment)]
    filter: Option<String>,

    /// The dir where the vanity keys are saved
    #[arg(short, long)]
    output: Option<String>,

    /// Device ID to use
    #[arg(short, long)]
    device: Option<usize>,

    /// Adjust it to maximum your device's usage
    #[arg(short, long)]
    thread: Option<usize>,

    /// Adjust it to maximum your device's usage
    #[arg(short, long, default_value_t = 1 << 9)]
    iteration: usize,

    /// Exit after a specified time in seconds
    #[arg(long)]
    timeout: Option<f64>,

    /// Exit after getting a vanity key
    #[arg(long, default_value_t = false)]
    oneshot: bool,

    /// Don't print progress
    #[arg(long, default_value_t = false)]
    no_progress: bool,

    /// Don't print armored secret key
    #[arg(long, default_value_t = false)]
    no_secret_key_logging: bool,

    /// Show available OpenCL devices then exit
    #[arg(long, default_value_t = false)]
    device_list: bool,
}

/// 手动进行SHA-1的填充操作
/// SHA-1的一个数据块是512 bit，因此输出的Vec<u32>长度是16的倍数
fn manually_prepare_sha1(hashdata: Vec<u8>) -> Vec<u32> {
    // 填充后的长度
    // 用80 00 ...填充到448 mod 512 bit即56 mod 64 bytes，加上u64的8 bytes后长度是64的倍数
    let padded_length = hashdata.len() + (64 - ((hashdata.len() + 8) % 64)) + 8;
    let mut result_u8 = Vec::with_capacity(padded_length);
    result_u8.extend_from_slice(&hashdata);
    result_u8.push(0x80);
    result_u8.resize(padded_length, 0);
    // 需要把Vec<u8>直接转换成Vec<u32>
    // https://stackoverflow.com/questions/49690459/converting-a-vecu32-to-vecu8-in-place-and-with-minimal-overhead
    let mut result_u32 = unsafe {
        let ptr = result_u8.as_mut_ptr() as *mut u32;
        let length = result_u8.len() / 4;
        let capacity = result_u8.capacity() / 4;
        mem::forget(result_u8);
        Vec::from_raw_parts(ptr, length, capacity)
    };
    // assert_eq!(result_u32.len() % 16, 0);
    // SHA-1的word和length使用大端序
    for i in 0..result_u32.len() {
        result_u32[i] = result_u32[i].to_be();
    }
    let bit_length = hashdata.len() * 8;
    result_u32[padded_length / 4 - 1] = (bit_length      ) as u32;
    result_u32[padded_length / 4 - 2] = (bit_length >> 32) as u32;
    result_u32
}

fn parse_pattern(pattern: String) -> (String, f64) {
    let pattern = match pattern.trim().replace(" ", "").to_ascii_uppercase() {
        x if x.len() <= 40 => "*".repeat(40 - x.len()) + &x,
        _ => panic!("Invalid pattern"),
    };
    let mut parts: Vec<String> = vec![];
    // 处理0-9A-F
    let mut fixed_pos_count: usize = 0;
    for i in 0..=4 {
        let mut mask = String::new();
        let mut value = String::new();
        let mut activated = false;
        for j in 0..8 {
            let char = *pattern.chars().nth(i * 8 + j).get_or_insert(' ');
            if char.is_ascii_hexdigit() {
                fixed_pos_count += 1;
                mask += "F";
                value += &String::from(char);
                activated = true;
            } else {
                mask += "0";
                value += "0";
            }
        }
        if activated {
            parts.push(format!("(h[{i}] & 0x{mask}) == 0x{value}"));
        }
    }
    // 处理通配符G-Z
    let mut wildcard_pos_all: [Vec<usize>; (b'Z' - b'G' + 1) as usize] = std::default::Default::default();
    for (i, wildcard) in pattern.chars().enumerate() {
        if ('G'..='Z').contains(&wildcard) {
            wildcard_pos_all[((wildcard as u8) - b'G') as usize].push(i);
        }
    }
    let mut wildcard_pos_count = 0;
    for wildcard in 'G'..='Z' {
        let wildcard_pos = &wildcard_pos_all[((wildcard as u8) - b'G') as usize];
        if wildcard_pos.len() >= 2 {
            for i in 1..wildcard_pos.len() {
                let left_index = wildcard_pos[i - 1] / 8;
                let right_index = wildcard_pos[i] / 8;
                let left_digit = 7 - wildcard_pos[i - 1] % 8;
                let right_digit = 7 - wildcard_pos[i] % 8;
                parts.push(format!(
                    "(/* {}: h[{}][{}] == h[{}][{}] */ (h[{}] {} {}) & 0xF{}) == (h[{}] & 0xF{})",
                    wildcard,
                    left_index,
                    left_digit,
                    right_index,
                    right_digit,
                    left_index,
                    if right_digit > left_digit { "<<" } else { ">>" },
                    right_digit.abs_diff(left_digit) * 4,
                    "0".repeat(right_digit),
                    right_index,
                    "0".repeat(right_digit),
                ));
            }
            wildcard_pos_count += wildcard_pos.len() - 1;
        }
    }
    let filter = if parts.len() != 0 {
        parts.join(" && ")
    } else {
        String::from("true")
    };
    (filter, (16f64).powi((fixed_pos_count + wildcard_pos_count) as i32))
}

fn format_number(v: impl Into<f64>) -> String {
    match Into::<f64>::into(v) {
        // v if v >= 1e9f64 => { return format!("{:.02}g", v / 1e9f64); },
        v if v >= 1e6f64 => { return format!("{:.02}m", v / 1e6f64); },
        v if v >= 1e3f64 => { return format!("{:.02}k", v / 1e3f64); },
        v => { return format!("{v:.02}"); },
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"))
        .format_indent(None)
        .init();

    let args = if cfg!(debug_assertions) {
        Args {
            cipher_suite: CipherSuite::RSA3072,
            user_id: String::from("Dummy <dummy@example.com>"),
            pattern: Some(String::from("XXXYYYZZZWWW")),
            filter: None,
            output: None,
            device: None,
            thread: None,
            iteration: 512,
            timeout: None,
            oneshot: true,
            no_progress: true,
            no_secret_key_logging: false,
            device_list: false,
        }
    } else {
        Args::parse()
    };
    debug!("{:?}", &args);

    let device_list: Vec<(Platform, Device)> = Platform::list()
        .iter()
        .rfold(
            Vec::new(),
            |mut list, platform| {
                match Device::list_all(platform) {
                    Ok(devices) => {
                        let mut devices = devices
                            .iter()
                            .map(|device| (*platform, *device))
                            .collect();
                        list.append(&mut devices);
                    },
                    Err(_) => {},
                }
                list
            },
        );
    if args.device_list {
        for (index, (platform, device)) in device_list.iter().enumerate() {
            info!("Device #{} - {}", index, format!(
                "{} ({}, MaxWorkGroupSize={}, MaxWorkItemSizes={}, MaxWorkItemDimensions={})",
                device.name()?,
                platform.name()?,
                device.info(ocl::core::DeviceInfo::MaxWorkGroupSize)?,
                device.info(ocl::core::DeviceInfo::MaxWorkItemSizes)?,
                device.info(ocl::core::DeviceInfo::MaxWorkItemDimensions)?,
            ));
        }
        return Ok(());
    }

    let device = match args.device {
        Some(i) =>  device_list[i].1,
        None => Device::first(Platform::default())?,
    };
    info!("Using device: {}", device.name()?);
    let dimension: usize = match args.thread {
        Some(v) => v,
        None => match device.info(ocl::core::DeviceInfo::MaxWorkItemSizes)? {
            ocl::core::DeviceInfoResult::MaxWorkItemSizes(wgs) => {
                let dimension = usize::max(wgs[0] * wgs[1], 1048576);
                info!("Auto set thread: {dimension}");
                dimension
            }
            _ => unreachable!(),
        },
    };
    let iteration: usize = args.iteration;
    info!(
        "You will get vanity keys created after {}",
        chrono::Utc::now()
            .checked_sub_signed(chrono::TimeDelta::seconds((dimension * iteration) as i64)).unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    );
    if let None = args.output {
        if args.no_secret_key_logging {
            warn!("No output dir given and you disabled secret key logging. You have no chance to save generated vanity keys.");
        } else {
            warn!("No output dir given. Generated vanity keys will not be saved.");
        }
    }

    let (filter, estimate) = match args.filter {
        Some(filter) => (filter, None),
        None => match args.pattern {
            Some(pattern) => {
                let (filter, estimate) = parse_pattern(pattern);
                (filter, Some(estimate))
            },
            None => panic!("No filter or pattern given"),
        },
    };
    debug!("Filter: {filter}");

    let mut rng = thread_rng();

    match args.cipher_suite {
        CipherSuite::RSA2048 | CipherSuite::RSA3072 | CipherSuite::RSA4096 => warn!("Generating RSA vanity keys is not recommended. Too slow!"),
        _ => (),
    };

    let mut vanity_key = VanitySecretKey::new(args.cipher_suite, args.user_id.clone(), &mut rng);
    let mut hashdata = manually_prepare_sha1(vanity_key.hashdata());

    let pro_que = ProQue::builder()
        .src(std::include_str!("shader.cl").replace(
            "#define __INJECTS__",
            &[
                format!("#define FILTER(h) ({filter})"),
                format!("#define CHUNK ({})", hashdata.len() / 16),
            ].join("\n"),
        ))
        .device(device)
        .dims(dimension)
        .build()?;

    let buffer_result = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(1)
        .fill_val(0)
        .build()?;

    let (tx_hashdata, rx_hashdata) = channel::<Vec<u32>>();
    let (tx_result, rx_result) = channel::<Option<u32>>();

    let mut hashed: usize = 0;
    let mut hashed_count: usize = 0;
    let mut start = Instant::now();

    thread::spawn(move || {
        let mut vec = vec![0; buffer_result.len()];
        debug!("OpenCL thread ready");
        while let Ok(hashdata) = rx_hashdata.recv() {
            buffer_result.cmd().fill(0, None).enq().unwrap();
            let buffer_hashdata = Buffer::<u32>::builder()
                .queue(pro_que.queue().clone())
                .len(hashdata.len())
                .copy_host_slice(&hashdata)
                .build().unwrap();
            let kernel = pro_que
                .kernel_builder("vanity_sha1")
                .arg(&buffer_hashdata)
                .arg(&buffer_result)
                .arg(iteration as u64)
                .build().unwrap();

            unsafe { kernel.enq().unwrap(); }

            buffer_result.read(&mut vec).enq().unwrap();
            tx_result.send(match vec[0] {
                0 => None,
                x => Some(x),
            }).unwrap();
        }
        debug!("OpenCL thread quit");
    });

    loop {
        debug!("Send key to OpenCL thread");
        tx_hashdata.send(hashdata)?;
        let vanity_key_next = VanitySecretKey::new(args.cipher_suite, args.user_id.clone(), &mut rng);
        let hashdata_next = manually_prepare_sha1(vanity_key_next.hashdata());

        debug!("Receive result from OpenCL thread");
        let vanity_timestamp = rx_result.recv()?;
        hashed += dimension * iteration;
        hashed_count += 1;
        let elapsed = start.elapsed().as_secs_f64();
        if !args.no_progress {
            match estimate {
                Some(estimate) => print!(
                    "[{}] {}/{} {:.02}x {:.02}s {} hash/s \r",
                    match hashed_count % 16 {
                        x if x < 8 => format!("{}>))'>{}", " ".repeat(     x), " ".repeat(7 - x)),
                        x          => format!("{}<'((<{}", " ".repeat(15 - x), " ".repeat(x - 8)),
                    },
                    format_number(hashed as f64),
                    format_number(estimate),
                    (hashed as f64) / estimate,
                    elapsed,
                    format_number((hashed as f64) / elapsed),
                ),
                None => print!(
                    "[{}] {} {:.02}s {} hash/s \r",
                    match hashed_count % 16 {
                        x if x < 8 => format!("{}>))'>{}", " ".repeat(     x), " ".repeat(7 - x)),
                        x          => format!("{}<'((<{}", " ".repeat(15 - x), " ".repeat(x - 8)),
                    },
                    format_number(hashed as f64),
                    elapsed,
                    format_number((hashed as f64) / elapsed),
                ),
            }
            io::stdout().flush()?;
        }

        match vanity_timestamp {
            Some(vanity_timestamp) => {
                vanity_key.edit_timestamp(vanity_timestamp, &mut rng);
                if args.no_secret_key_logging {
                    info!("Get a vanity key!");
                } else {
                    info!("Get a vanity key: \n{}", vanity_key.to_armored_string()?);
                }
                info!(
                    "Created at: {} ({})",
                    vanity_key.secret_key.created_at().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    vanity_key.secret_key.created_at().timestamp(),
                );
                info!("Fingerprint #0: {}", hex::encode_upper(vanity_key.secret_key.fingerprint().as_bytes()));
                for (i, subkey) in vanity_key.secret_key.secret_subkeys.iter().enumerate() {
                    info!("Fingerprint #{}: {}", i + 1, hex::encode_upper(subkey.fingerprint().as_bytes()));
                }
                match estimate {
                    Some(estimate) => info!(
                        "Hashed: {} ({:.02}x) Time: {:.02}s Speed: {} hash/s",
                        format_number(hashed as f64),
                        (hashed as f64) / estimate,
                        elapsed,
                        format_number((hashed as f64) / elapsed),
                    ),
                    None => info!(
                        "Hashed: {} Time: {:.02}s Speed: {} hash/s",
                        format_number(hashed as f64),
                        elapsed,
                        format_number((hashed as f64) / elapsed),
                    ),
                }
                if let Some(ref output_dir) = args.output {
                    fs::write(
                        Path::new(output_dir).join(format!("{}-sec.asc", hex::encode_upper(vanity_key.secret_key.fingerprint().as_bytes()))),
                        vanity_key.to_armored_string()?,
                    ).unwrap();
                }
                if args.oneshot {
                    break;
                }
                hashed = 0;
                start = Instant::now();
            },
            None => {},
        }
        if let Some(timeout) = args.timeout {
            if elapsed > timeout {
                info!("Timeout!");
                break;
            }
        }

        vanity_key = vanity_key_next;
        hashdata = hashdata_next;
    }

    Ok(())
}
