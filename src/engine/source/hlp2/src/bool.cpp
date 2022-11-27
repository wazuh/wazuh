
#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <string>
#include <json/json.hpp>
#include <optional>
#include <vector>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getBoolParser(Stop str, Options lst)
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

        if (index > fp.size())
            return parsec::makeError<json::Json>(
                fmt::format("Value is out of range in {}  at {}", text, index),
                text,
                index);

        if (fp.find("true", index) == 0)
        {
            return parsec::makeSuccess<json::Json>(json::Json("true"), text, index + 4);
        }
        else if (fp.find("false", index) == 0)
        {
            return parsec::makeSuccess<json::Json>(json::Json("false"), text, index + 5);
        }
        else
        {
            return parsec::makeError<json::Json>(
                fmt::format("Invalid input '{}'", text), text, index);
        }
    };
}
} // hlp namespace