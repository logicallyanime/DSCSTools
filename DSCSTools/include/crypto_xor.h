// crypto_xor.h
#pragma once
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include "MDB1.h"

namespace fast_xor_cipher {
constexpr size_t KEY1_LEN = 997;
constexpr size_t KEY2_LEN = 991;
constexpr size_t TOTAL_KEY_LEN = 988027; // 997 * 991

alignas(64) static std::array<uint8_t, TOTAL_KEY_LEN> COMBO{};
static std::once_flag combo_flag;

inline void init_combo() {
  for (size_t i = 0; i < TOTAL_KEY_LEN; ++i) {
    COMBO[i] = dscstools::mdb1::CRYPT_KEY_1[i % KEY1_LEN] ^
               dscstools::mdb1::CRYPT_KEY_2[i % KEY2_LEN];
  }
}

inline void xor_block(char* dst, const uint8_t* key, size_t blockSize) {
  size_t offset = 0;
  for (; offset + 8 <= blockSize; offset += 8) {
    uint64_t blockBuff, keyBuff;
    std::memcpy(&blockBuff, dst + offset, 8);
    std::memcpy(&keyBuff, key + offset, 8);
    blockBuff ^= keyBuff;
    std::memcpy(dst + offset, &blockBuff, 8);
  }
  for (; offset < blockSize; ++offset) dst[offset] ^= key[offset];
}

// XORs mapped bytes into dst, using absolute file offset for key index.
// If src != dst, copies first, then XORs in place.
inline void xor_into(const uint8_t* src,
                     char* dst,
                     size_t size,
                     uint64_t absOffset) {
  std::call_once(combo_flag, init_combo);

  if (src != reinterpret_cast<const uint8_t*>(dst)) {
    std::memcpy(dst, src, size);
  }

  size_t idx = static_cast<size_t>(absOffset % TOTAL_KEY_LEN);
  size_t rem = size;
  while (rem) {
    size_t chunkSize = (TOTAL_KEY_LEN - idx < rem) ? (TOTAL_KEY_LEN - idx) : rem;
    xor_block(dst, COMBO.data() + idx, chunkSize);
    dst += chunkSize;
    rem -= chunkSize;
    idx += chunkSize;
    if (idx == TOTAL_KEY_LEN) idx = 0;
  }
}
} // namespace mdb1_fastxor