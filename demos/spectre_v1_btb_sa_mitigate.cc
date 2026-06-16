/*
 * Copyright 2019 Google LLC
 *
 * Licensed under both the 3-Clause BSD License and the GPLv2, found in the
 * LICENSE and LICENSE.GPL-2.0 files, respectively, in the root directory.
 *
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
 */

// Mitigated variant of spectre_v1_btb_sa.cc.
//
// This demonstrates that inserting a double speculation barrier around the
// indirect branch (virtual function call) prevents the Spectre v1 BTB
// (Branch Target Buffer) mistraining attack from leaking data.
//
// HOW THE ATTACK WORKS (original):
//   The BTB is trained by repeatedly calling RealDataAccessor::GetDataByte
//   through a pointer array. On the critical iteration, the pointer is
//   swapped to CensoringDataAccessor, but the BTB mispredicts the indirect
//   branch target and speculatively jumps to RealDataAccessor::GetDataByte,
//   which reads private_data and encodes it into the cache.
//
// HOW THE DOUBLE-BARRIER MITIGATION WORKS:
//
//   Barrier 1 (pre-call): Placed immediately before the indirect branch
//   (the virtual call). This forces the CPU to architecturally resolve the
//   branch target (i.e., load the vtable pointer and compute the call
//   target address) before speculatively executing the call. When the BTB
//   would mispredict on the critical iteration, the barrier blocks
//   speculative execution from jumping to the wrong vtable entry.
//
//   Barrier 2 (post-call / pre-ForceRead): Placed after the virtual call
//   returns but before ForceRead uses the returned byte. This is a
//   defense-in-depth measure: even if some microarchitectural state from
//   the mispredicted path survives Barrier 1 (e.g., due to implementation
//   quirks on certain microarchitectures), Barrier 2 ensures that no
//   speculative data can propagate into the cache side channel.
//
//   Together, the two barriers close both the primary speculation window
//   (before the indirect branch) and any residual window (after the call
//   returns), providing robust mitigation against BTB-based Spectre v1.
//
// EXPECTED RESULT:
//   Unlike the original spectre_v1_btb_sa, this variant should NOT leak
//   private_data. The program will likely fail to converge, demonstrating
//   that the double barrier effectively closes the side channel.
//
// PLATFORM NOTES:
//   This program should build and run on any platform supported by the
//   original spectre_v1_btb_sa demo.

#include <cstring>
#include <iostream>

#include "cache_sidechannel.h"
#include "instr.h"
#include "utils.h"

const char *public_data = "xxxxxxxxxxxxxxxx";
const char *private_data = "It's a s3kr3t!!!";
constexpr size_t kAccessorArrayLength = 1024;

class DataAccessor {
 public:
  virtual char GetDataByte(size_t index, bool read_from_private_data) = 0;
  virtual ~DataAccessor() {};
 protected:
  const char *GetDataPtr(bool read_from_private_data) const {
    return public_data + (
        private_data - public_data) * static_cast<int>(read_from_private_data);
  }
};

class RealDataAccessor: public DataAccessor {
 public:
  char GetDataByte(size_t index, bool read_from_private_data) override {
    return GetDataPtr(read_from_private_data)[index];
  }
};

class CensoringDataAccessor: public DataAccessor {
 public:
  char GetDataByte(size_t index, bool /* read_from_private_data */) override {
    return public_data[index];
  }
};

// Attempts to leak private_data[offset] using the same BTB mistraining
// technique as spectre_v1_btb_sa, but with a double speculation barrier
// that should prevent the leak.
static char LeakByte(size_t offset) {
  CacheSideChannel sidechannel;
  const std::array<BigByte, 256> &oracle = sidechannel.GetOracle();
  auto array_of_pointers =
      std::unique_ptr<std::array<DataAccessor *, kAccessorArrayLength>>(
          new std::array<DataAccessor *, kAccessorArrayLength>());

  auto real_data_accessor = std::unique_ptr<DataAccessor>(
      new RealDataAccessor);

  auto censoring_data_accessor = std::unique_ptr<DataAccessor>(
      new CensoringDataAccessor);

  for (int run = 0;; ++run) {
    sidechannel.FlushOracle();

    for (auto &pointer : *array_of_pointers) {
      pointer = real_data_accessor.get();
    }

    size_t local_pointer_index = run % kAccessorArrayLength;
    (*array_of_pointers)[local_pointer_index] = censoring_data_accessor.get();

    for (size_t i = 0; i <= local_pointer_index; ++i) {
      DataAccessor *accessor = (*array_of_pointers)[i];
      bool read_private_data = (i == local_pointer_index);

      size_t object_size_in_bytes = sizeof(
          RealDataAccessor) + (sizeof(CensoringDataAccessor) - sizeof(
              RealDataAccessor)) * (i == local_pointer_index);

      const char *accessor_bytes = reinterpret_cast<const char*>(accessor);
      FlushFromDataCache(accessor_bytes, accessor_bytes + object_size_in_bytes);

      // === MITIGATION: Double speculation barrier ===
      //
      // Barrier 1 (pre-call):
      // Forces the CPU to architecturally resolve the indirect branch
      // target before executing the virtual call. This prevents the BTB
      // from speculatively jumping to RealDataAccessor::GetDataByte when
      // the actual target is CensoringDataAccessor::GetDataByte.
      //
      // Without this barrier, on the critical iteration (i ==
      // local_pointer_index), the BTB predicts the call target based on
      // the previous 1023+ iterations that all called
      // RealDataAccessor::GetDataByte. The CPU speculatively executes
      // RealDataAccessor::GetDataByte(offset, true), which reads
      // private_data[offset] and encodes it into the cache.
      MemoryAndSpeculationBarrier();

      char result_byte = accessor->GetDataByte(offset, read_private_data);

      // Barrier 2 (post-call / pre-ForceRead):
      // Defense-in-depth. Even if some speculative state from a
      // mispredicted indirect branch survives Barrier 1 (possible on
      // certain microarchitectures with complex branch prediction
      // structures), this barrier ensures that no speculative data
      // propagates into the ForceRead below.
      //
      // The barrier serializes execution: the CPU must architecturally
      // retire the virtual call and all preceding instructions before
      // proceeding to ForceRead. Any transient execution effects from
      // the mispredicted path are discarded.
      MemoryAndSpeculationBarrier();

      // Speculative fetch at the offset. With the double barrier in
      // place, result_byte is guaranteed to be the architecturally
      // correct value (from CensoringDataAccessor on the critical
      // iteration), so only public_data enters the cache.
      ForceRead(oracle.data() + static_cast<size_t>(result_byte));
    }

    std::pair<bool, char> result =
        sidechannel.RecomputeScores(public_data[offset]);
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
  std::cout << "Attempting to leak the string (with BTB double-barrier"
            << " mitigation): ";
  std::cout.flush();
  for (size_t i = 0; i < strlen(public_data); ++i) {
    std::cout << LeakByte(i);
    std::cout.flush();
  }
  std::cout << "\nDone!\n";
}
