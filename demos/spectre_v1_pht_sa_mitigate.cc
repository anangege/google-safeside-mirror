/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// Mitigated variant of spectre_v1_pht_sa.cc.
//
// This demonstrates that inserting a MemoryAndSpeculationBarrier() between
// the bounds check and the subsequent memory access prevents the Spectre v1
// PHT (Pattern History Table) mistraining attack from leaking data.
//
// HOW THE ATTACK WORKS (original):
//   The branch predictor is trained to always take the bounds-check branch
//   (2047 in-bounds accesses). On the 2048th iteration with an out-of-bounds
//   offset, the CPU speculatively executes past the branch before the
//   condition is resolved, performing an out-of-bounds read that leaks
//   secret data into the cache.
//
// HOW THE MITIGATION WORKS:
//   MemoryAndSpeculationBarrier() (lfence on x86, dsb+isb on ARM, etc.) is
//   inserted after the bounds check but before the ForceRead. This forces
//   the CPU to architecturally resolve the branch condition before
//   proceeding. When the branch is mispredicted on the 2048th iteration,
//   the barrier blocks speculative execution from reaching the out-of-bounds
//   memory access, so no secret data enters the cache.
//
// EXPECTED RESULT:
//   Unlike the original spectre_v1_pht_sa, this variant should NOT leak
//   private_data. The program will likely print garbage or fail to converge,
//   demonstrating that the barrier effectively closes the side channel.
//
// PLATFORM NOTES:
//   This program should build and run on any platform supported by the
//   original spectre_v1_pht_sa demo.

#include <cstring>
#include <iostream>
#include <memory>

#include "instr.h"
#include "local_content.h"
#include "timing_array.h"
#include "utils.h"

// Attempts to leak the byte at &text[0] + offset using the same PHT
// mistraining technique as spectre_v1_pht_sa, but with a speculation
// barrier that should prevent the leak.
//
// The barrier is placed between the bounds check and the ForceRead call.
// This ensures the CPU must architecturally resolve the branch condition
// before any subsequent memory access, preventing speculative out-of-bounds
// reads.
static char LeakByte(const char *data, size_t offset) {
  TimingArray timing_array;
  std::unique_ptr<size_t> size_in_heap = std::unique_ptr<size_t>(
      new size_t(strlen(data)));

  for (int run = 0;; ++run) {
    timing_array.FlushFromCache();
    int safe_offset = run % strlen(data);

    for (size_t i = 0; i < 2048; ++i) {
      FlushDataCacheLine(size_in_heap.get());

      // Same branchless offset selection as the original:
      // safe_offset for iterations 0..2046, secret offset for iteration 2047.
      size_t local_offset =
          offset + (safe_offset - offset) * static_cast<bool>((i + 1) % 2048);

      if (local_offset < *size_in_heap) {
        // === MITIGATION: speculation barrier ===
        //
        // This barrier forces the CPU to architecturally resolve the branch
        // condition above before executing any subsequent instructions.
        // On x86 this is lfence; on ARM it is dsb ld + isb; on PPC it is
        // the equivalent serializing sequence.
        //
        // When the branch predictor mispredicts on the 2048th iteration
        // (local_offset >= *size_in_heap), the barrier prevents speculative
        // execution from reaching the ForceRead below. The out-of-bounds
        // read never happens -- not even speculatively -- so no secret
        // data is loaded into the cache.
        MemoryAndSpeculationBarrier();

        ForceRead(&timing_array[data[local_offset]]);
      }
    }

    int ret = timing_array.FindFirstCachedElementIndexAfter(data[safe_offset]);
    if (ret >= 0 && ret != data[safe_offset]) {
      return ret;
    }

    if (run > 100000) {
      std::cerr << "Does not converge" << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}

int main() {
  std::cout << "Attempting to leak the string (with PHT mitigation): ";
  std::cout.flush();
  const size_t private_offset = private_data - public_data;
  for (size_t i = 0; i < strlen(private_data); ++i) {
    std::cout << LeakByte(public_data, private_offset + i);
    std::cout.flush();
  }
  std::cout << "\nDone!\n";
}
