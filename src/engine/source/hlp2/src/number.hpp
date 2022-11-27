#ifndef WAZUH_ENGINE_NUMBER_HPP
#define WAZUH_ENGINE_NUMBER_HPP

#include "fmt/format.h"
#include <charconv>
#include <hlp/parsec.hpp>
#include <iostream>
#include <string>
#include <optional>
#include <vector>
#include <json/json.hpp>
#include <cmath>
#include <fast_float/fast_float.h>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace utils {
void setNumber(json::Json& doc, int8_t val);
void setNumber(json::Json& doc, int64_t val);
void setNumber(json::Json& doc, float_t val);
void setNumber(json::Json& doc, double_t val);
std::from_chars_result from_chars(const char* first, const char* last, int8_t& val);
std::from_chars_result from_chars(const char* first, const char* last, int64_t& val);
std::from_chars_result from_chars(const char* first, const char* last, float& val);
std::from_chars_result from_chars(const char* first, const char* last, double& val);
}

namespace hlp {
void updateDoc(json::Json & doc, std::string_view hdr, std::string_view val, bool is_escaped, std::string_view escape);

template<class T>
parsec::Parser<json::Json> getNumericParser(Stop str, Options lst)
{
    return [str](std::string_view text, int index)
    {
        T val {};

        size_t pos = text.size();
        std::string_view fp = text;
        if (str.has_value() && ! str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }

        auto [ptr, ec] {utils::from_chars(fp.data()+index, fp.data()+fp.size(), val)};
        if (ec == std::errc())
        {
            auto pos = ptr - fp.data();
            json::Json doc;
            utils::setNumber(doc,val);
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }
        else if (ec == std::errc::invalid_argument)
        {
            return parsec::makeError<json::Json>(fmt::format("Input '{}' is not a number at {}", text, index), text, index);
        }
        else if (ec == std::errc::result_out_of_range)
        {
            return parsec::makeError<json::Json>(fmt::format("Value is out of range in {}  at {}", text, index), text, index);
        }

        return parsec::makeError<json::Json>(fmt::format("Unknown error when parsing '{}' at {}",text, index), text, index);
    };
}



}
#endif // WAZUH_ENGINE_NUMBER_HPP
