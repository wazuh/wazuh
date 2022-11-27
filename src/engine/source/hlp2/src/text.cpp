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
parsec::Parser<json::Json> getTextParser(Stop str, Options lst)
{
    if (!str.has_value())
    {
        throw std::invalid_argument(fmt::format("Text parser needs a stop string"));
    }

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

        json::Json doc;
        auto t = text.substr(index, pos);
        // copy can be slow
        doc.setString(std::string {t});
        return parsec::makeSuccess<json::Json>(doc, text, pos);
    };
}
}
