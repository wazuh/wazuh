#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <string>
#include <json/json.hpp>
#include <optional>
#include <vector>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;



inline bool is_valid_base64_char(char c)
{
    if ((c >= 'A') && (c <= 'Z'))
    {
        return true;
    }

    if ((c >= 'a') && ('z'))
    {
        return true;
    }

    if ((c >= '0') && (c <= '9'))
    {
        return true;
    }

    if ((c == '+') || (c == '/'))
    {
        return true;
    }

    return false;
}

namespace hlp {

parsec::Parser<json::Json> getBinaryParser(Stop str, Options lst)
{
    return [str](std::string_view text, int index)
    {

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

        auto it = std::find_if(std::begin(fp) + index,
                               std::end(fp),
                               [](char c) { return !is_valid_base64_char(c); });

        auto size = it - std::begin(fp);
        if (size == 0)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Invalid char '{}' found at '{}'", *it, index), text, index);
        }
        // consume up to two '=' padding chars
        if (*it == '=')
        {
            size++;
            auto nx = std::next(it);
            if (*nx == '=')
                size++;
        }

        if ((size % 4) != 0)
        {
            return parsec::makeError<json::Json>(
                fmt::format("Wrong string size '{}' for base64 from offset {} to {}",
                            size,
                            index,
                            size),
                text,
                index);
        }
        json::Json doc;
        // copy can be slow
        doc.setString(std::string {text.substr(index, size)});
        return parsec::makeSuccess<json::Json>(doc, text, size);
    };
}
} // hlp namespace
