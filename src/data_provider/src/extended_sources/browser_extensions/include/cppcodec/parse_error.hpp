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

#ifndef CPPCODEC_PARSE_ERROR
#define CPPCODEC_PARSE_ERROR

#include <stdexcept>
#include <string>

namespace cppcodec
{

    namespace detail
    {
        // <*stream> headers include a lot of code and noticeably increase compile times.
        // The only thing we want from them really is a char-to-string conversion.
        // That's easy to implement with many less lines of code, so let's do it ourselves.
        template <int N>
        static void uctoa(unsigned char n, char (&s)[N])
        {
            static_assert(N >= 4, "need at least 4 bytes to convert an unsigned char to string safely");
            int i = sizeof(s) - 1;
            int num_chars = 1;
            s[i--] = '\0';

            do   // generate digits in reverse order
            {
                s[i--] = n % 10 + '0'; // get next digit
                ++num_chars;
            }
            while ((n /= 10) > 0);   // delete it

            if (num_chars == sizeof(s))
            {
                return;
            }

            for (i = 0; i < num_chars; ++i)   // move chars to front of string
            {
                s[i] = s[i + (sizeof(s) - num_chars)];
            }
        }
    } // end namespace detail


    class parse_error : public std::domain_error
    {
        public:
            using std::domain_error::domain_error;
    };

    // Avoids memory allocation, so it can be used in constexpr functions.
    class symbol_error : public parse_error
    {
        public:
            symbol_error(char c)
                : parse_error(symbol_error::make_error_message(c))
                , m_symbol(c)
            {
            }

            symbol_error(const symbol_error&) = default;

            char symbol() const noexcept
            {
                return m_symbol;
            }

        private:
            static std::string make_error_message(char c)
            {
                char s[4];
                detail::uctoa(*reinterpret_cast<unsigned char*>(&c), s);
                return std::string("parse error: character [") + &(s[0]) + " '" + c + "'] out of bounds";
            }

        private:
            char m_symbol;
    };

    class invalid_input_length : public parse_error
    {
        public:
            using parse_error::parse_error;
    };

    class padding_error : public invalid_input_length
    {
        public:
            padding_error()
                : invalid_input_length("parse error: codec expects padded input string but padding was invalid")
            {
            }

            padding_error(const padding_error&) = default;
    };

} // namespace cppcodec

#endif // CPPCODEC_PARSE_ERROR
