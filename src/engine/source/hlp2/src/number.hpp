#ifndef _HLP_NUMBER_HPP
#define _HLP_NUMBER_HPP

#include <charconv>
#include <cmath>
#include <fast_float/fast_float.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <hlp/base.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace utils
{
void setNumber(json::Json& doc, int8_t val);
void setNumber(json::Json& doc, int64_t val);
void setNumber(json::Json& doc, float_t val);
void setNumber(json::Json& doc, double_t val);
std::from_chars_result from_chars(const char* first, const char* last, int8_t& val);
std::from_chars_result from_chars(const char* first, const char* last, int64_t& val);
std::from_chars_result from_chars(const char* first, const char* last, float& val);
std::from_chars_result from_chars(const char* first, const char* last, double& val);
} // namespace utils

namespace hlp
{

template<class T>
parsec::Parser<json::Json> getNumericParser(Stop, Options lst)
{
    if (!lst.empty())
    {
        throw std::runtime_error("numeric parser doesn't accept parameters");
    }

    return [](std::string_view text, int index)
    {
        T val {};

        auto error = internal::eofError<json::Json>(text, index);
        if (error.has_value())
        {
            return error.value();
        }

        auto [ptr, ec] {utils::from_chars(text.begin() + index, text.end(), val)};
        if (ec == std::errc())
        {
            auto pos = ptr - text.begin();
            json::Json doc;
            utils::setNumber(doc, val);
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }
        else if (ec == std::errc::invalid_argument)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Input '{}' is not a number at {}", text, index),
                text,
                index);
        }
        else if (ec == std::errc::result_out_of_range)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Value is out of range in {}  at {}", text, index),
                text,
                index);
        }

        return parsec::makeError<json::Json>(
            fmt::format("Unknown error when parsing '{}' at {}", text, index),
            text,
            index);
    };
}

} // namespace hlp
#endif // _HLP_NUMBER_HPP
