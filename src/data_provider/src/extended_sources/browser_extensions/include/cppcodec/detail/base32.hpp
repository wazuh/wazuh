/**
 *  Copyright (C) 2015 Trustifier Inc.
 *  Copyright (C) 2015 Ahmed Masud
 *  Copyright (C) 2015 Topology LP
 *  Copyright (C) 2018 Jakob Petsovits
 *  All rights reserved.
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to
 *  deal in the Software without restriction, including without limitation the
 *  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 *  sell copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 *  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 *  IN THE SOFTWARE.
 *
 *  Adapted from https://github.com/ahmed-masud/libbase32,
 *  commit 79761b2b79b0545697945efe0987a8d3004512f9.
 *  Quite different now.
 */

#ifndef CPPCODEC_DETAIL_BASE32
#define CPPCODEC_DETAIL_BASE32

#include <stdint.h>
#include <stdlib.h> // for abort()

#include "../data/access.hpp"
#include "../parse_error.hpp"
#include "config.hpp"
#include "stream_codec.hpp"

namespace cppcodec {
namespace detail {

template <typename CodecVariant>
class base32 : public CodecVariant::template codec_impl<base32<CodecVariant>>
{
public:
    static inline constexpr uint8_t binary_block_size() { return 5; }
    static inline constexpr uint8_t encoded_block_size() { return 8; }

    static CPPCODEC_ALWAYS_INLINE constexpr uint8_t num_encoded_tail_symbols(uint8_t num_bytes)
    {
        return (num_bytes == 1) ? 2    // 2 symbols, 6 padding characters
                : (num_bytes == 2) ? 4 // 4 symbols, 4 padding characters
                : (num_bytes == 3) ? 5 // 5 symbols, 3 padding characters
                : (num_bytes == 4) ? 7 // 7 symbols, 1 padding characters
                : throw std::domain_error("invalid number of bytes in a tail block");
    }

    template <uint8_t I>
    static CPPCODEC_ALWAYS_INLINE constexpr uint8_t index(
            const uint8_t* b /*binary block*/) noexcept
    {
        static_assert(I >= 0 && I < encoded_block_size(),
                "invalid encoding symbol index in a block");

        return (I == 0) ? ((b[0] >> 3) & 0x1F) // first 5 bits
                : (I == 1) ? (((b[0] << 2) & 0x1C) | ((b[1] >> 6) & 0x3))
                : (I == 2) ? ((b[1] >> 1) & 0x1F)
                : (I == 3) ? (((b[1] << 4) & 0x10) | ((b[2] >> 4) & 0xF))
                : (I == 4) ? (((b[2] << 1) & 0x1E) | ((b[3] >> 7) & 0x1))
                : (I == 5) ? ((b[3] >> 2) & 0x1F)
                : (I == 6) ? (((b[3] << 3) & 0x18) | ((b[4] >> 5) & 0x7))
                : /*I == 7*/ (b[4] & 0x1F); // last 5 bits;
    }

    template <bool B>
    using uint8_if = typename std::enable_if<B, uint8_t>::type;

    template <uint8_t I>
    static CPPCODEC_ALWAYS_INLINE constexpr
    uint8_if<I == 1 || I == 3 || I == 4 || I == 6> index_last(
            const uint8_t* b /*binary block*/) noexcept
    {
        return (I == 1) ? ((b[0] << 2) & 0x1C)     // abbreviated 2nd symbol
                : (I == 3) ? ((b[1] << 4) & 0x10)  // abbreviated 4th symbol
                : (I == 4) ? ((b[2] << 1) & 0x1E)  // abbreviated 5th symbol
                : /*I == 6*/ ((b[3] << 3) & 0x18); // abbreviated 7th symbol
    }

    template <uint8_t I>
    static CPPCODEC_ALWAYS_INLINE
    uint8_if<I != 1 && I != 3 && I != 4 && I != 6> index_last(
            const uint8_t* /*binary block*/)
    {
        throw std::domain_error("invalid last encoding symbol index in a tail");
    }

    template <typename Result, typename ResultState>
    static CPPCODEC_ALWAYS_INLINE void decode_block(
            Result& decoded, ResultState&, const alphabet_index_t* idx);

    template <typename Result, typename ResultState>
    static CPPCODEC_ALWAYS_INLINE void decode_tail(
            Result& decoded, ResultState&, const alphabet_index_t* idx, size_t idx_len);
};

//
//     11111111 10101010 10110011  10111100 10010100
// => 11111 11110 10101 01011 00111 01111 00100 10100
//

template <typename CodecVariant>
template <typename Result, typename ResultState>
CPPCODEC_ALWAYS_INLINE void base32<CodecVariant>::decode_block(
        Result& decoded, ResultState& state, const alphabet_index_t* idx)
{
    put(decoded, state, static_cast<uint8_t>(((idx[0] << 3) & 0xF8) | ((idx[1] >> 2) & 0x7)));
    put(decoded, state, static_cast<uint8_t>(((idx[1] << 6) & 0xC0) | ((idx[2] << 1) & 0x3E) | ((idx[3] >> 4) & 0x1)));
    put(decoded, state, static_cast<uint8_t>(((idx[3] << 4) & 0xF0) | ((idx[4] >> 1) & 0xF)));
    put(decoded, state, static_cast<uint8_t>(((idx[4] << 7) & 0x80) | ((idx[5] << 2) & 0x7C) | ((idx[6] >> 3) & 0x3)));
    put(decoded, state, static_cast<uint8_t>(((idx[6] << 5) & 0xE0) | (idx[7] & 0x1F)));
}

template <typename CodecVariant>
template <typename Result, typename ResultState>
CPPCODEC_ALWAYS_INLINE void base32<CodecVariant>::decode_tail(
        Result& decoded, ResultState& state, const alphabet_index_t* idx, size_t idx_len)
{
    if (idx_len == 1) {
        throw invalid_input_length(
                "invalid number of symbols in last base32 block: found 1, expected 2, 4, 5 or 7");
    }
    if (idx_len == 3) {
        throw invalid_input_length(
                "invalid number of symbols in last base32 block: found 3, expected 2, 4, 5 or 7");
    }
    if (idx_len == 6) {
        throw invalid_input_length(
                "invalid number of symbols in last base32 block: found 6, expected 2, 4, 5 or 7");
    }

    // idx_len == 2: decoded size 1
    put(decoded, state, static_cast<uint8_t>(((idx[0] << 3) & 0xF8) | ((idx[1] >> 2) & 0x7)));
    if (idx_len == 2) {
        return;
    }
    // idx_len == 4: decoded size 2
    put(decoded, state, static_cast<uint8_t>(((idx[1] << 6) & 0xC0) | ((idx[2] << 1) & 0x3E) | ((idx[3] >> 4) & 0x1)));
    if (idx_len == 4) {
        return;
    }
    // idx_len == 5: decoded size 3
    put(decoded, state, static_cast<uint8_t>(((idx[3] << 4) & 0xF0) | ((idx[4] >> 1) & 0xF)));
    if (idx_len == 5) {
        return;
    }
    // idx_len == 7: decoded size 4
    put(decoded, state, static_cast<uint8_t>(((idx[4] << 7) & 0x80) | ((idx[5] << 2) & 0x7C) | ((idx[6] >> 3) & 0x3)));
}

} // namespace detail
} // namespace cppcodec

#endif // CPPCODEC_DETAIL_BASE32
