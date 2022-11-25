#include "fmt/format.h"
#include <charconv>
#include <hlp/parsec.hpp>
#include <iostream>
#include <string>
#include <optional>
#include <vector>
#include <json/json.hpp>
#include <cmath>

#ifndef WAZUH_ENGINE_BASIC_HPP
#define WAZUH_ENGINE_BASIC_HPP

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;


void setNumber(json::Json & doc, int8_t val) {
    doc.setInt(val);
}

void setNumber(json::Json & doc, float_t val) {
    doc.setFloat(val);
}

void setNumber(json::Json & doc, double_t val) {
    doc.setDouble(val);
}

void setNumber(json::Json & doc, int64_t val) {
    doc.setInt64(val);
}

namespace hlp {

template<class T>
parsec::Parser<json::Json> getNumericParser(Stop str, Options lst)
{
    return [](std::string_view text, int index)
    {
        T val {};

        auto [ptr, ec] {std::from_chars(text.data()+index, text.data()+text.size(), val)};
        if (ec == std::errc())
        {
            auto pos = ptr - text.data();
            auto l = text.substr(index, pos); // substr can throw if index > size()
            json::Json doc;
            setNumber(doc,val);
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
#endif // WAZUH_ENGINE_BASIC_HPP
