// Fuzzing harness for the SMM probe library.
// This feeds mutated (smi_val, data_byte) pairs into a latency model
// and flags anything that runs significantly slower than baseline.

use std::time::{Duration, Instant};

#[repr(C)]
pub struct SmmProbeReport {
    pub dram_latency_ns: u64,
    pub smm_latency_ns:  u64,
    pub n_regions:       u32,
    pub n_pages:         u32,
}

extern "C" {
    fn smm_probe_run(out: *mut SmmProbeReport) -> i32;
}

/// The two bytes we actually mutate: the SMI command and the data port value.
#[derive(Debug, Clone, Copy)]
pub struct SmiInput {
    pub smi_val:  u8,
    pub data_val: u8,
}

impl SmiInput {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 2 { return None; }
        Some(SmiInput { smi_val: b[0], data_val: b[1] })
    }
}

/// A fake latency model so we can fuzz offline without real hardware.
/// It's a simple lookup table based on what we've seen in the wild.
#[cfg(not(feature = "live_smi"))]
fn dispatch_latency_ns(input: SmiInput, baseline_ns: u64) -> u64 {
    let extra = match input.smi_val {
        0x00..=0x0F => 0,                     // these are usually quick no‑ops
        0x52        => baseline_ns * 3,       // vendor‑specific hook, often heavy
        0xA0..=0xFF => baseline_ns / 2,       // default handler, takes a while
        _           => baseline_ns / 4,       // everything else is somewhere in between
    };
    baseline_ns + extra + (input.data_val as u64 * 10)
}

/// Actually trigger an SMI and measure the round‑trip time.
/// This only gets used when you build with `--features=live_smi`.
#[cfg(feature = "live_smi")]
fn dispatch_latency_ns(input: SmiInput, _baseline_ns: u64) -> u64 {
    use std::arch::asm;
    let t0 = Instant::now();
    unsafe {
        asm!("out dx, al", in("dx") 0xB3u16, in("al") input.data_val);
        asm!("out dx, al", in("dx") 0xB2u16, in("al") input.smi_val);
    }
    t0.elapsed().as_nanos() as u64
}

/// Returns `true` if the input's latency is >1.5× the baseline.
/// libFuzzer uses this to focus mutations on promising areas.
pub fn fuzz_target(data: &[u8], baseline_ns: u64) -> bool {
    let input = match SmiInput::from_bytes(data) {
        Some(i) => i,
        None    => return false,
    };

    let latency = dispatch_latency_ns(input, baseline_ns);
    let interesting = latency > (baseline_ns * 3 / 2);

    if interesting {
        eprintln!("[harness] interesting: SMI=0x{:02X} data=0x{:02X} latency={}ns",
                  input.smi_val, input.data_val, latency);
    }

    interesting
}

/// A quick standalone test that runs all 65536 combinations through the model.
fn main() {
    let mut report = SmmProbeReport {
        dram_latency_ns: 0,
        smm_latency_ns:  0,
        n_regions:       0,
        n_pages:         0,
    };

    let baseline = unsafe {
        smm_probe_run(&mut report);
        if report.dram_latency_ns > 0 { report.dram_latency_ns } else { 100 }
    };

    println!("Baseline DRAM: {}ns  SW SMI latency: {}ns", baseline, report.smm_latency_ns);
    println!("Sweeping 256×256 inputs through latency model...");

    let mut hits = 0u32;
    for smi in 0u8..=255 {
        for data in 0u8..=255 {
            let buf = [smi, data];
            if fuzz_target(&buf, baseline) { hits += 1; }
        }
    }

    println!("Interesting inputs: {}/65536", hits);
}

/// libFuzzer entry point – called automatically by `cargo fuzz`.
#[cfg(fuzzing)]
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    let buf = unsafe { std::slice::from_raw_parts(data, size) };
    fuzz_target(buf, 100);
    0
}
