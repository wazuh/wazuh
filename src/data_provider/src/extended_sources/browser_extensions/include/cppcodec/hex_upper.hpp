/**
 *  Copyright (C) 2015 Topology LP
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

#ifndef CPPCODEC_HEX_UPPER
#define CPPCODEC_HEX_UPPER

#include "detail/codec.hpp"
#include "detail/hex.hpp"

namespace cppcodec
{

    namespace detail
    {

        static constexpr const char hex_upper_alphabet[] =
        {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'A', 'B', 'C', 'D', 'E', 'F'
        };

        class hex_upper
        {
            public:
                template <typename Codec> using codec_impl = stream_codec<Codec, hex_upper>;

                static CPPCODEC_ALWAYS_INLINE constexpr size_t alphabet_size()
                {
                    static_assert(sizeof(hex_upper_alphabet) == 16, "hex alphabet must have 16 values");
                    return sizeof(hex_upper_alphabet);
                }
                static CPPCODEC_ALWAYS_INLINE constexpr char symbol(alphabet_index_t index)
                {
                    return hex_upper_alphabet[index];
                }
                static CPPCODEC_ALWAYS_INLINE constexpr char normalized_symbol(char c)
                {
                    // Hex decoding is always case-insensitive (even in RFC 4648), the question
                    // is only for encoding whether to use upper-case or lower-case letters.
                    return (c >= 'a' && c <= 'f') ? (c - 'a' + 'A') : c;
                }

                static CPPCODEC_ALWAYS_INLINE constexpr bool generates_padding()
                {
                    return false;
                }
                // FIXME: doesn't require padding, but requires a multiple of the encoded block size (2)
                static CPPCODEC_ALWAYS_INLINE constexpr bool requires_padding()
                {
                    return false;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_padding_symbol(char)
                {
                    return false;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_eof_symbol(char c)
                {
                    return c == '\0';
                }

                // Sometimes hex strings include whitespace, but this variant forbids it.
                static CPPCODEC_ALWAYS_INLINE constexpr bool should_ignore(char)
                {
                    return false;
                }
        };

    } // namespace detail

    using hex_upper = detail::codec<detail::hex<detail::hex_upper>>;

} // namespace cppcodec

#endif // CPPCODEC_HEX_UPPER
