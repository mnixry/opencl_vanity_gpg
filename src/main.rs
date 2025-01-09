use anyhow::bail;
use log::*;
use ocl::{Buffer, Device, Platform, ProQue};
use pgp::types::PublicKeyTrait;
use rand::thread_rng;
use std::{
    fs,
    path::Path,
    str::FromStr,
    sync::{mpsc::*, LazyLock},
    thread,
    time::Instant,
};
use utils::ARGS;
use utils::*;

mod utils;

fn main() -> anyhow::Result<()> {
    let bars = init_logger();

    debug!("{:#?}", LazyLock::force(&ARGS));

    let device_list = utils::DeviceList::new()?;

    if ARGS.list_device {
        info!("Available OpenCL devices: \n");
        for (i, device) in device_list.iter().enumerate() {
            println!("Device #{} - {:?}", i, device);
        }
        return Ok(());
    }

    let device = match ARGS.device {
        Some(i) => device_list[i].device,
        None => Device::first(Platform::default())?,
    };

    info!("Using device: {}", device.name()?);

    let dimension = match ARGS.thread {
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

    let iteration = ARGS.iteration;
    info!(
        "You will get vanity keys created after {}",
        chrono::Utc::now()
            .checked_sub_signed(chrono::TimeDelta::seconds((dimension * iteration) as i64))
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    );

    if ARGS.output.is_none() {
        if ARGS.no_secret_key_logging {
            warn!("No output dir given and you disabled secret key logging. You have no chance to save generated vanity keys.");
        } else {
            warn!("No output dir given. Generated vanity keys will not be saved.");
        }
    }

    let pattern = match &ARGS.pattern {
        Some(pattern) => Some(HashPattern::from_str(pattern)?),
        None => None,
    };

    let (filter, estimate) = match &ARGS.filter {
        Some(filter) => (filter.clone(), None),
        None => match &pattern {
            Some(p) => (p.filter.clone(), Some(p.possibliity)),
            None => bail!("No filter or pattern given"),
        },
    };
    debug!("Filter: {filter}");

    let mut rng = thread_rng();

    match ARGS.cipher_suite {
        CipherSuite::RSA2048 | CipherSuite::RSA3072 | CipherSuite::RSA4096 => {
            warn!("Generating RSA vanity keys is not recommended. Too slow!")
        }
        _ => (),
    };

    let mut vanity_key = VanitySecretKey::new(ARGS.cipher_suite, ARGS.user_id.clone(), &mut rng);
    let mut hashdata = manually_prepare_sha1(vanity_key.hashdata());

    let (tx_hashdata, rx_hashdata) = channel::<Vec<u32>>();
    let (tx_result, rx_result) = channel::<Option<u32>>();

    let mut hashed = 0;
    let mut start = Instant::now();

    let pro_que = ProQue::builder()
        .src(
            std::include_str!("shader.cl").replace(
                "#define __INJECTS__",
                &[
                    format!("#define FILTER(h) ({filter})"),
                    format!("#define CHUNK ({})", hashdata.len() / 16),
                ]
                .join("\n"),
            ),
        )
        .device(device)
        .dims(dimension)
        .build()?;

    let buffer_result = Buffer::<u32>::builder()
        .queue(pro_que.queue().clone())
        .len(1)
        .fill_val(0)
        .build()?;

    thread::spawn(move || opencl_thread(buffer_result, pro_que, rx_hashdata, tx_result));

    let bench_size = (dimension * iteration) as u64;
    let bar = bars.add(init_progress_bar(estimate));

    loop {
        debug!("Send key to OpenCL thread");
        tx_hashdata.send(hashdata)?;
        let vanity_key_next =
            VanitySecretKey::new(ARGS.cipher_suite, ARGS.user_id.clone(), &mut rng);
        let hashdata_next = manually_prepare_sha1(vanity_key_next.hashdata());

        debug!("Receive result from OpenCL thread");
        let vanity_timestamp = rx_result.recv()?;
        hashed += bench_size;

        let elapsed = start.elapsed().as_secs_f64();
        bar.inc(bench_size);

        if let Some(vanity_timestamp) = vanity_timestamp {
            vanity_key.edit_timestamp(vanity_timestamp, &mut rng);

            if match &pattern {
                Some(pattern) => vanity_key.check_pattern(pattern),
                None => true,
            } {
                vanity_key.log_state();

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

                if let Some(ref output_dir) = ARGS.output {
                    fs::write(
                        Path::new(output_dir).join(format!(
                            "{}-sec.asc",
                            hex::encode_upper(vanity_key.secret_key.fingerprint().as_bytes())
                        )),
                        vanity_key.to_armored_string()?,
                    )
                    .unwrap();
                }

                if ARGS.oneshot {
                    bar.finish();
                    bars.clear()?;
                    break;
                }

                hashed = 0;
                bar.reset();
                start = Instant::now();
            }
        }

        if let Some(timeout) = ARGS.timeout {
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

fn opencl_thread(
    buffer_result: Buffer<u32>,
    pro_que: ProQue,
    rx_hashdata: Receiver<Vec<u32>>,
    tx_result: Sender<Option<u32>>,
) {
    let mut vec = vec![0; buffer_result.len()];
    debug!("OpenCL thread ready");
    while let Ok(hashdata) = rx_hashdata.recv() {
        buffer_result.cmd().fill(0, None).enq().unwrap();

        let buffer_hashdata = Buffer::<u32>::builder()
            .queue(pro_que.queue().clone())
            .len(hashdata.len())
            .copy_host_slice(&hashdata)
            .build()
            .unwrap();

        let kernel = pro_que
            .kernel_builder("vanity_sha1")
            .arg(&buffer_hashdata)
            .arg(&buffer_result)
            .arg(ARGS.iteration as u64)
            .build()
            .unwrap();

        unsafe {
            kernel.enq().unwrap();
        }

        buffer_result.read(&mut vec).enq().unwrap();

        tx_result
            .send(match vec[0] {
                0 => None,
                x => Some(x),
            })
            .unwrap();
    }
    debug!("OpenCL thread quit");
}
