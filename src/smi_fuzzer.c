// Sweep all 256 possible SW SMI values and report any that take
// significantly longer than a no‑op SMI.

#define _GNU_SOURCE          // for clock_gettime and CLOCK_MONOTONIC_RAW

#include "../include/smi_fuzzer.h"
#include "../include/smm_probe.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/io.h>
#include <time.h>

#define INTERESTING_RATIO   1.5
#define SAMPLES_PER_VAL     32

// Measure the median round‑trip latency for a single SMI value.
static uint64_t sample_smi(uint8_t val) {
    uint64_t s[SAMPLES_PER_VAL];
    struct timespec t0, t1;

    for (int i = 0; i < SAMPLES_PER_VAL; i++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
        outb(val, SMI_PORT);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
        s[i] = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
             + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    }

    // Simple insertion sort – 32 elements is tiny.
    for (int i = 1; i < SAMPLES_PER_VAL; i++) {
        uint64_t k = s[i]; int j = i - 1;
        while (j >= 0 && s[j] > k) { s[j+1] = s[j]; j--; }
        s[j+1] = k;
    }
    return s[SAMPLES_PER_VAL / 2];
}

int smi_fuzz_sweep(SmiResult *out, unsigned *n_interesting, uint64_t baseline_ns) {
    if (ioperm(SMI_PORT, 2, 1) < 0) {
        fprintf(stderr, "[fuzz] ioperm failed — need root + iopl\n");
        return -1;
    }

    *n_interesting = 0;

    // Known dangerous values that trigger power state changes.
    static const uint8_t dangerous[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,  // ACPI sleep / soft‑off
        0x0A, 0x0B,                           // S4/S5 on some platforms
        0x52,                                 // Common OEM shutdown hook
    };

    for (int v = 0; v < 256; v++) {      
        int skip = 0;
        for (size_t i = 0; i < sizeof(dangerous); i++) {
            if (v == dangerous[i]) {
                skip = 1;
                break;
            }
        }
        if (skip) {
            out[v].smi_val    = (uint8_t)v;
            out[v].median_ns  = 0;
            out[v].interesting = 0;
            continue;
        }
        out[v].smi_val    = (uint8_t)v;
        out[v].median_ns  = sample_smi((uint8_t)v);
        out[v].interesting = (baseline_ns > 0 &&
            (double)out[v].median_ns > INTERESTING_RATIO * (double)baseline_ns) ? 1 : 0;
        if (out[v].interesting) (*n_interesting)++;

        // Print progress every 16 values so we don't look stuck.
        if ((v & 0xF) == 0xF)
            fprintf(stderr, "[fuzz] 0x%02X–0x%02X done  interesting so far: %u\n",
                    v - 15, v, *n_interesting);
    }

    ioperm(SMI_PORT, 2, 0);
    return 0;
}

void smi_fuzz_print(const SmiResult *results, unsigned n_interesting) {
    printf("\n=== SMI Fuzz Results ===\n");
    printf("Interesting values (%u / 256):\n", n_interesting);

    for (int v = 0; v < 256; v++) {
        if (results[v].interesting)
            printf("  SMI=0x%02X  median=%lu ns\n",
                   results[v].smi_val, results[v].median_ns);
    }
}
