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

namespace {
/**
 * @brief Return the dsv parser function
 *
 * @param endTokens
 * @param delimiter
 * @param quote
 * @param escape
 * @param headers
 * @return parsec::Parser<json::Json>
 */
inline auto dsvParserFunction(Stop endTokens,
                              const char delimiterChar,
                              const char quoteChar,
                              const char scapeChar,
                              std::vector<std::string> headers)
    -> parsec::Parser<json::Json>
{
    if (endTokens.empty())
    {
        throw std::runtime_error(fmt::format("CSV/DSV parser needs a stop string"));
    }
    return [endTokens, delimiterChar, quoteChar, headers, scapeChar](std::string_view text, int index)
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
            auto f = getField(fp.begin(), start, fp.size(), delimiterChar, quoteChar, scapeChar, true);
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
                fmt::format("Unable to parse from {} to {}", end, pos), end);

        return parsec::makeSuccess<json::Json>(std::move(doc), end);
    };
}
}

parsec::Parser<json::Json> getDSVParser(Stop endTokens, Options lst)
{

    if (lst.size() < 5)
    {
        throw std::runtime_error(
            fmt::format("Need at least five options: delim, quote, escape characters and two headers"));
    }
    else if(lst[0].size() != 1 || lst[1].size() != 1 || lst[2].size() != 1)
    {
        throw std::runtime_error(
            fmt::format("Delim, quote and escape characters must be single characters"));
    }

    const char delimiter = lst[0][0];
    const char quote = lst[1][0];
    const char scape = lst[2][0];

    std::vector<std::string> headers;
    std::transform(std::next(lst.begin(), 3),
                   lst.end(),
                   std::back_inserter(headers),
                   [](auto s) { return fmt::format("/{}", s); });

    return dsvParserFunction(endTokens, delimiter, quote, scape, headers);
}

parsec::Parser<json::Json> getCSVParser(Stop endTokens, Options lst)
{

    if (lst.size() < 2)
    {
        throw std::runtime_error(
            fmt::format("CSV parser need at least two headers"));
    }

    const char delimiter = ',';
    const char quote = '"';
    const char scape = '"';

    std::vector<std::string> headers;
    std::transform(lst.begin(),
                   lst.end(),
                   std::back_inserter(headers),
                   [](auto s) { return fmt::format("/{}", s); });

    return dsvParserFunction(endTokens, delimiter, quote, scape, headers);
}


} // namespace hlp
