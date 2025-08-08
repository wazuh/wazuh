/**
 *  Copyright (C) 2016 Topology LP
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

#ifndef CPPCODEC_BASE64_URL_UNPADDED
#define CPPCODEC_BASE64_URL_UNPADDED

#include "base64_url.hpp"

namespace cppcodec
{

    namespace detail
    {

        class base64_url_unpadded : public base64_url
        {
            public:
                template <typename Codec> using codec_impl = stream_codec<Codec, base64_url_unpadded>;

                static CPPCODEC_ALWAYS_INLINE constexpr bool generates_padding()
                {
                    return false;
                }
                static CPPCODEC_ALWAYS_INLINE constexpr bool requires_padding()
                {
                    return false;
                }
        };

    } // namespace detail

    using base64_url_unpadded = detail::codec<detail::base64<detail::base64_url_unpadded>>;

} // namespace cppcodec

#endif // CPPCODEC_BASE64_URL_UNPADDED
