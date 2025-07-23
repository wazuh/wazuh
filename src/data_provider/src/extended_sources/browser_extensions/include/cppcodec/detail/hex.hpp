/**
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
 */

#ifndef CPPCODEC_DETAIL_HEX
#define CPPCODEC_DETAIL_HEX

#include <stdint.h>
#include <stdlib.h> // for abort()

#include "../data/access.hpp"
#include "../parse_error.hpp"
#include "stream_codec.hpp"

namespace cppcodec {
namespace detail {

template <typename CodecVariant>
class hex : public CodecVariant::template codec_impl<hex<CodecVariant>>
{
public:
    static inline constexpr uint8_t binary_block_size() { return 1; }
    static inline constexpr uint8_t encoded_block_size() { return 2; }

    static CPPCODEC_ALWAYS_INLINE constexpr uint8_t num_encoded_tail_symbols(uint8_t /*num_bytes*/) noexcept
    {
        // Hex encoding only works on full bytes so there are no tails,
        // no padding characters, and this function should (must) never be called.
        return 0;
    }

    template <uint8_t I>
    static CPPCODEC_ALWAYS_INLINE constexpr uint8_t index(
            const uint8_t* b /*binary block*/) noexcept
    {
        static_assert(I >= 0 && I < encoded_block_size(),
                "invalid encoding symbol index in a block");

        return (I == 0) ? (b[0] >> 4) // first 4 bits
                : /*I == 1*/ (b[0] & 0xF); // last 4 bits
    }

    // With only 2 bytes, enc<1> will always result in a full index() call and
    // enc<0> will be protected by a not-reached assertion, so we don't actually
    // care about index_last() except optimizing it out as good as possible.
    template <bool B>
    using uint8_if = typename std::enable_if<B, uint8_t>::type;

    template <uint8_t I>
    static CPPCODEC_ALWAYS_INLINE constexpr uint8_if<I == 0> index_last(
            const uint8_t* /*binary block*/) noexcept
    {
        return 0;
    }

    template <uint8_t I>
    static CPPCODEC_ALWAYS_INLINE uint8_if<I != 0> index_last(
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


template <typename CodecVariant>
template <typename Result, typename ResultState>
CPPCODEC_ALWAYS_INLINE void hex<CodecVariant>::decode_block(
        Result& decoded, ResultState& state, const alphabet_index_t* idx)
{
    data::put(decoded, state, static_cast<uint8_t>((idx[0] << 4) | idx[1]));
}

template <typename CodecVariant>
template <typename Result, typename ResultState>
CPPCODEC_ALWAYS_INLINE void hex<CodecVariant>::decode_tail(
        Result&, ResultState&, const alphabet_index_t*, size_t)
{
    throw invalid_input_length(
            "odd-length hex input is not supported by the streaming octet decoder, "
            "use a place-based number decoder instead");
}

} // namespace detail
} // namespace cppcodec

#endif // CPPCODEC_DETAIL_HEX
