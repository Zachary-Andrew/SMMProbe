// Command‑line driver for the SMM probe and fuzzer.

#define _GNU_SOURCE

#include "../include/smm_probe.h"
#include "../include/smi_fuzzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *p) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --probe      map SMRAM boundaries and measure SMI latency (default)\n"
        "  --fuzz       sweep all 256 SW SMI values for handler anomalies\n"
        "  --all        run both\n"
        "  -h           this help\n\n"
        "Requires root.  On Linux: sudo %s --probe\n",
        p, p);
}

int main(int argc, char **argv) {
    int do_probe = 1, do_fuzz = 0;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--fuzz")  == 0) { do_probe = 0; do_fuzz = 1; }
        else if (strcmp(argv[i], "--all")   == 0) { do_probe = 1; do_fuzz = 1; }
        else if (strcmp(argv[i], "--probe") == 0) { do_probe = 1; }
        else if (strcmp(argv[i], "-h")      == 0) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "Unknown: %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    SmmProbeReport report;
    if (do_probe) {
        if (smm_probe_run(&report) < 0) {
            fprintf(stderr, "Probe failed — are you root?\n");
            return 1;
        }
        smm_probe_print(&report);
    }

    if (do_fuzz) {
        uint64_t baseline = do_probe ? report.smm_latency_ns : 0;
        SmiResult results[256];
        unsigned n_interesting = 0;

        if (smi_fuzz_sweep(results, &n_interesting, baseline) < 0) return 1;
        smi_fuzz_print(results, n_interesting);
    }

    return 0;
}
