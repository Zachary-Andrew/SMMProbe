#pragma once

#include <stdint.h>

// A single SMI value's fuzzing result.
typedef struct {
    uint8_t  smi_val;
    uint64_t median_ns;      // median latency over 32 samples
    uint8_t  interesting;    // true if >1.5× baseline
} SmiResult;

int  smi_fuzz_sweep(SmiResult *out, unsigned *n_interesting, uint64_t baseline_ns);
void smi_fuzz_print(const SmiResult *results, unsigned n_interesting);
