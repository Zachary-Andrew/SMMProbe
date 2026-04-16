#pragma once

#include <stdint.h>
#include <stddef.h>

// I/O ports for triggering a software SMI.
#define SMI_PORT        0xB2
#define SMI_DATA_PORT   0xB3

// The legacy SMRAM window is always at 0xA0000 (128 KB).
#define SMRAM_LEGACY_BASE   0x000A0000UL
#define SMRAM_LEGACY_SIZE   0x00020000UL

// We probe memory in 4 KB chunks and keep at most 512 results.
#define PROBE_PAGE_SIZE     0x1000UL
#define PROBE_MAX_PAGES     512

// A candidate SMRAM region we've found (TSEG or legacy).
typedef struct {
    uint64_t base;
    uint64_t size;
    uint8_t  locked;      // D_LCK or equivalent
    uint8_t  tseg;        // 1 if TSEG, 0 if legacy window
    uint8_t  pad[6];
} SmramRegion;

// Result from probing a single page.
typedef struct {
    uint8_t  smi_val;     // SMI value that triggered a fault (if any)
    uint64_t rip_delta;   // not currently used but kept for future
    uint8_t  faulted;     // 1 if mmap of this page failed
    uint8_t  pad[3];
} ProbeResult;

// Everything the probe collects in one place.
typedef struct {
    SmramRegion regions[8];
    unsigned    n_regions;

    ProbeResult pages[PROBE_MAX_PAGES];
    unsigned    n_pages;

    uint64_t    dram_latency_ns;   // baseline pointer‑chase latency
    uint64_t    smm_latency_ns;    // measured round‑trip for SMI 0x00
} SmmProbeReport;

int  smm_probe_run(SmmProbeReport *out);
void smm_probe_print(const SmmProbeReport *r);
