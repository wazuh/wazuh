#include "fmt/format.h"
#include "number.hpp"
#include "parse_field.hpp"
#include <algorithm>
#include <hlp/parsec.hpp>
#include <iostream>
#include <json/json.hpp>
#include <optional>
#include <vector>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{

parsec::Parser<json::Json> getCSVParser(Stop str, Options lst)
{

    if (lst.size() < 4)
    {
        throw std::invalid_argument(
            fmt::format("Need at least four options: delim, quote, and two headers"));
    }

    const char delimiter = lst[0][0];
    const char quote = lst[1][0];

    std::vector<std::string> headers;
    std::transform(std::next(lst.begin(), 2),
                   lst.end(),
                   std::back_inserter(headers),
                   [](auto s) { return fmt::format("/{}", s); });

    return [str, delimiter, quote, headers](std::string_view text, int index)
    {
        size_t start {0}, end {0};
        json::Json doc;

        size_t pos = text.size();
        std::string_view fp = text;
        if (str.has_value() && !str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()),
                    text,
                    index);
            }
            fp = text.substr(index, pos);
        }

        auto i = 0;
        while (end <= fp.size())
        {
            auto f = getField(fp.begin(), start, fp.size(), delimiter, quote, '"', true);
            if (!f.has_value())
                break;

            if (i >= headers.size())
                break;

            auto fld = f.value();
            end = fld.end_;

            auto v = fp.substr(fld.start(), fld.len());
            updateDoc(doc, headers[i], v, fld.is_escaped, R"(")");

            start = fld.end_ + 1;
            i++;
        }

        if (end < pos && headers.size() != i)
            return parsec::makeError<json::Json>(
                fmt::format("Unable to parse from {} to {}", end, pos), text, index);

        return parsec::makeSuccess<json::Json>(doc, text, end);
    };
}
} // namespace hlp
