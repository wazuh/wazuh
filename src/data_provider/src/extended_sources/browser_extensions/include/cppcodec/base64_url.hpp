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

#ifndef CPPCODEC_BASE64_URL
#define CPPCODEC_BASE64_URL

#include "detail/codec.hpp"
#include "detail/base64.hpp"

namespace cppcodec
{

    namespace detail
    {

        // The URL and filename safe alphabet is also specified by RFC4648, named "base64url".
        // We keep the underscore ("base64_url") for consistency with the other codec variants.
        static constexpr const char base64_url_alphabet[] =
        {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
        };

        class base64_url
        {
            public:
                template <typename Codec> using codec_impl = stream_codec<Codec, base64_url>;

                static CPPCODEC_ALWAYS_INLINE constexpr size_t alphabet_size()
                {
                    static_assert(sizeof(base64_url_alphabet) == 64, "base64 alphabet must have 64 values");
                    return sizeof(base64_url_alphabet);
                }
                static CPPCODEC_ALWAYS_INLINE constexpr char symbol(alphabet_index_t idx)
                {
                    return base64_url_alphabet[idx];
                }
                static CPPCODEC_ALWAYS_INLINE constexpr char normalized_symbol(char c)
                {
                    return c;
                }

                static CPPCODEC_ALWAYS_INLINE constexpr bool generates_padding()
                {
                    return true;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool requires_padding()
                {
                    return true;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr char padding_symbol()
                {
                    return '=';
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_padding_symbol(char c)
                {
                    return c == '=';
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool is_eof_symbol(char c)
                {
                    return c == '\0';
                }

                // RFC4648 does not specify any whitespace being allowed in base64 encodings.
                static CPPCODEC_ALWAYS_INLINE constexpr bool should_ignore(char)
                {
                    return false;
                }
        };

    } // namespace detail

    using base64_url = detail::codec<detail::base64<detail::base64_url>>;

} // namespace cppcodec

#endif // CPPCODEC_BASE64_URL
