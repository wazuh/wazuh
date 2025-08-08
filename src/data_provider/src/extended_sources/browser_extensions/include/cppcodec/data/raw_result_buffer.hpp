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

#ifndef CPPCODEC_DETAIL_RAW_RESULT_BUFFER
#define CPPCODEC_DETAIL_RAW_RESULT_BUFFER

#include <stdint.h> // for size_t
#include <stdlib.h> // for abort()

#include "access.hpp"

namespace cppcodec
{
    namespace data
    {

        class raw_result_buffer
        {
            public:
                raw_result_buffer(char* data, size_t capacity)
                    : m_ptr(data + capacity)
                    , m_begin(data)
                {
                }

                CPPCODEC_ALWAYS_INLINE void push_back(char c)
                {
                    *m_ptr = c;
                    ++m_ptr;
                }
                CPPCODEC_ALWAYS_INLINE size_t size() const
                {
                    return m_ptr - m_begin;
                }
                CPPCODEC_ALWAYS_INLINE void resize(size_t size)
                {
                    m_ptr = m_begin + size;
                }

            private:
                char* m_ptr;
                char* m_begin;
        };


        template <> inline void init<raw_result_buffer>(
            raw_result_buffer& result, empty_result_state&, size_t capacity)
        {
            // This version of init() doesn't do a reserve(), and instead checks whether the
            // initial size (capacity) is enough before resetting m_ptr to m_begin.
            // The codec is expected not to exceed this capacity.
            if (capacity > result.size())
            {
                abort();
            }

            result.resize(0);
        }
        template <> inline void finish<raw_result_buffer>(raw_result_buffer&, empty_result_state&) { }

    } // namespace data
} // namespace cppcodec

#endif
