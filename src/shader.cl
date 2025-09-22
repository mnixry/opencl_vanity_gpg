#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define __INJECTS__
#ifdef __INJECTS__
#define CHUNK (0)
#define FILTER(h) (false)
#define FUTURE_MODE (0)
#endif

// Enable 32-bit global atomics for result publishing
#pragma OPENCL EXTENSION cl_khr_global_int32_base_atomics : enable

__kernel void vanity_sha1(__global const uint *hashdata, __global uint *results, const uint datalen, const ulong iter, const uint max_time_range) {
    uint data[CHUNK * 16];
    
    uint thread_id = get_global_id(0);
    uint batch_idx = get_global_id(1);
    uint base = batch_idx * (CHUNK * 16);
    for (uint i = 0; i < CHUNK * 16; i++) data[i] = hashdata[base + i];
    uint nonce = data[1];
    
    for (uint i = 0; i < iter; i++) {
        // Use a simple sequential approach that searches close to base time first
        // Each thread gets a small sequential offset
        uint offset = thread_id + i * get_global_size(0);
        
        // Wrap around within max_time_range to avoid going too far
        offset = offset % max_time_range;
        
        if (FUTURE_MODE) {
            // For future mode: increment timestamp within range
            data[1] = nonce + offset;
            // Check for overflow
            if (data[1] < nonce) break;
        } else {
            // For past mode: decrement timestamp within range
            data[1] = nonce - offset;
            // Check for underflow
            if (data[1] > nonce) break;
        }

        uint h[] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

        #pragma unroll
        for (uint chunk = 0; chunk < CHUNK; chunk++) {
            uint w[80];
            for (int i = 0; i < 16; i++) w[i] = data[chunk * 16 + i];
            for (int i = 16; i < 80; i++) w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

            uint a = h[0];
            uint b = h[1];
            uint c = h[2];
            uint d = h[3];
            uint e = h[4];
            uint f;
            uint k;
            uint t;

            #pragma unroll
            for (int i = 0; i < 80; i++) {
                if (i < 20) {
                    f = d ^ (b & (c ^ d));
                    k = 0x5A827999;
                } else if (i < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (i < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                t = ROTL(a, 5) + f + e + k + w[i];
                e = d;
                d = c;
                c = ROTL(b, 30);
                b = a;
                a = t;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
        }

        if (FILTER(h)) {
            // Publish first-found timestamp for this batch index
            atomic_cmpxchg((volatile __global int *)&results[batch_idx], 0, (int)data[1]);
            break;
        }
    }
}