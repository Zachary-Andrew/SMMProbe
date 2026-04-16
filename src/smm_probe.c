// Main probing logic: find SMRAM regions, test page accessibility,
// measure baseline DRAM latency, and trigger a test SMI.

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "../include/smm_probe.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/io.h>
#include <sys/mman.h>

// MSRs that tell us where SMRAM lives.
#define MSR_SMM_BASE        0xC0010111
#define MSR_SMRR_BASE       0x1F2
#define MSR_SMRR_MASK       0x1F3

// PCI config space for the host bridge (bus 0, device 0, function 0).
#define PCI_MCH_BDF         0x80000000UL
#define PCI_TSEG_BASE_OFF   0xB0
#define PCI_TSEG_MASK_OFF   0xB4
#define PCI_CF8             0xCF8
#define PCI_CFC             0xCFC

static int mem_fd = -1;   // /dev/mem
static int msr_fd = -1;   // /dev/cpu/0/msr

static int open_devs(void) {
    mem_fd = open("/dev/mem", O_RDONLY);
    msr_fd = open("/dev/cpu/0/msr", O_RDONLY);
    return (mem_fd >= 0) ? 0 : -1;
}

static void close_devs(void) {
    if (mem_fd >= 0) { close(mem_fd); mem_fd = -1; }
    if (msr_fd >= 0) { close(msr_fd); msr_fd = -1; }
}

// Read a 64‑bit MSR from CPU 0.
static int read_msr(uint32_t index, uint64_t *val) {
    if (msr_fd < 0) return -1;
    return pread(msr_fd, val, 8, (off_t)index) == 8 ? 0 : -1;
}

// Classic CF8/CFC PCI config read.
static uint32_t pci_read32(uint32_t bdf_base, uint8_t offset) {
    uint32_t addr = bdf_base | (offset & 0xFC) | 0x80000000UL;
    if (ioperm(PCI_CF8, 8, 1) < 0) return 0xFFFFFFFF;
    outl(addr, PCI_CF8);
    uint32_t val = inl(PCI_CFC);
    ioperm(PCI_CF8, 8, 0);
    return val;
}

// Use Intel SMRR MSRs to locate TSEG.
static int detect_smrr(SmramRegion *r) {
    uint64_t base = 0, mask = 0;
    if (read_msr(MSR_SMRR_BASE, &base) < 0 ||
        read_msr(MSR_SMRR_MASK, &mask) < 0)
        return -1;

    if (!(mask & (1 << 11))) return -1;   // valid bit not set

    uint64_t size = (~mask & 0xFFFFF000ULL) + 0x1000ULL;
    r->base   = base & 0xFFFFF000ULL;
    r->size   = size;
    r->tseg   = 1;
    r->locked = 1;
    return 0;
}

// Fallback: read TSEG base/mask from PCI config space.
static int detect_tseg_pci(SmramRegion *r) {
    uint32_t tseg_base = pci_read32(PCI_MCH_BDF, PCI_TSEG_BASE_OFF);
    uint32_t tseg_mask = pci_read32(PCI_MCH_BDF, PCI_TSEG_MASK_OFF);

    if (tseg_base == 0xFFFFFFFF || tseg_mask == 0xFFFFFFFF) return -1;

    r->base   = tseg_base & 0xFFF00000UL;
    r->size   = (~tseg_mask & 0xFFF00000UL) + 0x100000UL;
    r->tseg   = 1;
    r->locked = (tseg_base & 0x2) ? 1 : 0;
    return 0;
}

// Always add the legacy 0xA0000 window as a fallback candidate.
static void add_legacy_smram(SmramRegion *r) {
    r->base   = SMRAM_LEGACY_BASE;
    r->size   = SMRAM_LEGACY_SIZE;
    r->tseg   = 0;
    r->locked = 0;
}

// Try to mmap one page from physical memory; returns 0 if we can read it.
static int probe_phys_page(uint64_t phys, uint8_t *buf) {
    if (mem_fd < 0) return -1;
    void *m = mmap(NULL, PROBE_PAGE_SIZE, PROT_READ, MAP_SHARED,
                   mem_fd, (off_t)phys);
    if (m == MAP_FAILED) return -1;
    memcpy(buf, m, PROBE_PAGE_SIZE);
    munmap(m, PROBE_PAGE_SIZE);
    return 0;
}

#define SMI_LATENCY_SAMPLES 64

// Time how long it takes to send an SMI and return to userspace.
static uint64_t measure_smi_latency_ns(uint8_t smi_val) {
    if (ioperm(SMI_PORT, 2, 1) < 0) return 0;

    uint64_t samples[SMI_LATENCY_SAMPLES];
    struct timespec t0, t1;

    for (int i = 0; i < SMI_LATENCY_SAMPLES; i++) {
        clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
        outb(smi_val, SMI_PORT);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
        samples[i] = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                   + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    }

    ioperm(SMI_PORT, 2, 0);

    for (int i = 1; i < SMI_LATENCY_SAMPLES; i++) {
        uint64_t key = samples[i];
        int j = i - 1;
        while (j >= 0 && samples[j] > key) { samples[j+1] = samples[j]; j--; }
        samples[j+1] = key;
    }
    return samples[SMI_LATENCY_SAMPLES / 2];
}

// Pointer‑chase through a 32 MB shuffled buffer to measure DRAM access time.
static uint64_t measure_dram_ns(void) {
    const size_t BUF = 32 * 1024 * 1024;
    const size_t N   = BUF / 64;

    size_t *nodes = mmap(NULL, BUF, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (nodes == MAP_FAILED) return 100;   // fallback guess

    // Fill with sequential indices.
    for (size_t i = 0; i < N; i++) nodes[i] = i;
    // Shuffle using a simple LCG.
    uint64_t rng = 0xDEADBEEFCAFEULL;
    for (size_t i = N - 1; i > 0; i--) {
        rng = rng * 6364136223846793005ULL + 1;
        size_t j = rng % (i + 1);
        size_t tmp = nodes[i]; nodes[i] = nodes[j]; nodes[j] = tmp;
    }

    volatile size_t idx = 0;
    for (size_t i = 0; i < N; i++) idx = nodes[idx];   // warm up

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t0);
    for (int r = 0; r < 4; r++)
        for (size_t i = 0; i < N; i++) idx = nodes[idx];
    clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
    (void)idx;

    munmap(nodes, BUF);

    uint64_t ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL
                + (uint64_t)(t1.tv_nsec - t0.tv_nsec);
    return ns / (N * 4);
}

int smm_probe_run(SmmProbeReport *out) {
    memset(out, 0, sizeof(*out));

    open_devs();

    out->dram_latency_ns = measure_dram_ns();

    // Build the list of candidate SMRAM regions, best source first.
    SmramRegion *reg = out->regions;
    if (detect_smrr(&reg[out->n_regions]) == 0)      out->n_regions++;
    if (detect_tseg_pci(&reg[out->n_regions]) == 0)  out->n_regions++;
    add_legacy_smram(&reg[out->n_regions++]);

    // Probe each page in each candidate region.
    uint8_t page_buf[PROBE_PAGE_SIZE];
    for (unsigned ri = 0; ri < out->n_regions && out->n_pages < PROBE_MAX_PAGES; ri++) {
        uint64_t addr = out->regions[ri].base;
        uint64_t end  = addr + out->regions[ri].size;

        for (; addr < end && out->n_pages < PROBE_MAX_PAGES; addr += PROBE_PAGE_SIZE) {
            ProbeResult *pr = &out->pages[out->n_pages++];
            pr->faulted = (probe_phys_page(addr, page_buf) < 0) ? 1 : 0;
        }
    }

    // Measure a no‑op SMI to get a baseline handler latency.
    out->smm_latency_ns = measure_smi_latency_ns(0x00);

    close_devs();
    return 0;
}

void smm_probe_print(const SmmProbeReport *r) {
    printf("=== SMM Probe Report ===\n");
    printf("DRAM baseline:    %lu ns\n", r->dram_latency_ns);
    printf("SW SMI latency:   %lu ns  (no-op SMI=0x00)\n", r->smm_latency_ns);
    printf("\nSMRAM Regions (%u found):\n", r->n_regions);

    for (unsigned i = 0; i < r->n_regions; i++) {
        const SmramRegion *reg = &r->regions[i];
        printf("  [%u] base=0x%016lx  size=0x%lx  %s  %s\n",
               i, reg->base, reg->size,
               reg->tseg   ? "TSEG"   : "legacy",
               reg->locked ? "LOCKED" : "open");
    }

    unsigned faulted = 0;
    for (unsigned i = 0; i < r->n_pages; i++)
        if (r->pages[i].faulted) faulted++;

    printf("\nPage probe: %u/%u pages caused access fault (protected)\n",
           faulted, r->n_pages);

    if (r->dram_latency_ns > 0) {
        double ratio = (double)r->smm_latency_ns / (double)r->dram_latency_ns;
        printf("SMI/DRAM ratio:   %.1fx  (%s)\n", ratio,
               ratio > 2.0 ? "handler likely dispatched" : "may have been dropped");
    }
}
