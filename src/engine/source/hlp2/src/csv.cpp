#include <algorithm>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <vector>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

#include "number.hpp"
#include "parse_field.hpp"

namespace hlp
{

parsec::Parser<json::Json> getCSVParser(Stop endTokens, Options lst)
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

    return [endTokens, delimiter, quote, headers](std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);

        size_t start {0}, end {0};
        auto pos = fp.size() + index;
        json::Json doc;

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
