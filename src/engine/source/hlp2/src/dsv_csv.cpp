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

namespace
{
/**
 * @brief Return the dsv parser function
 *
 * @param endTokens The tokens that end the text, e.g. "EOF"
 * @param delimiter The delimiter character
 * @param quote The quote character for quoted fields
 * @param escape The escape character for quoted fields
 * @param headers The header names (destination)
 * @return parsec::Parser<json::Json>
 */
inline auto dsvParserFunction(std::string name,
                              Stop endTokens,
                              const char delimiterChar,
                              const char quoteChar,
                              const char escapeChar,
                              std::vector<std::string> headers)
    -> parsec::Parser<json::Json>
{
    if (endTokens.empty())
    {
        throw std::runtime_error(fmt::format("CSV/DSV parser needs a stop string"));
    }
    return [endTokens, delimiterChar, quoteChar, headers, escapeChar, name](
               std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto rawText = std::get<std::string_view>(res);
        std::size_t start {0};

        json::Json doc {};
        auto i = 0;

        while (start <= rawText.size() && i < headers.size())
        {
            auto remaining = rawText.substr(start, rawText.size() - start);
            auto field = getField(remaining,
                                  delimiterChar,
                                  quoteChar,
                                  escapeChar,
                                  true);

            if (!field.has_value())
            {
                break;
            }

            auto fValue = field.value();

            auto v = remaining.substr(fValue.start(), fValue.len());
            updateDoc(doc, headers[i], v, fValue.isEscaped(), std::string {escapeChar}, fValue.isQuoted());

            start += fValue.end() + 1;
            i++;
        }

        auto end = start + index - 1;
        if (headers.size() != i)
        {
            return parsec::makeError<json::Json>(
                fmt::format("{}: Expected a DSV/CSV string", name), start + index);
        }
        return parsec::makeSuccess<json::Json>(std::move(doc), end);
    };
}
} // namespace

parsec::Parser<json::Json> getDSVParser(std::string name, Stop endTokens, Options lst)
{
    if (lst.size() < 5)
    {
        throw std::runtime_error(fmt::format("Need at least five options: delim, quote, "
                                             "escape characters and two headers"));
    }
    else if (lst[0].size() != 1 || lst[1].size() != 1 || lst[2].size() != 1)
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

    return dsvParserFunction(name, endTokens, delimiter, quote, scape, headers);
}

parsec::Parser<json::Json> getCSVParser(std::string name, Stop endTokens, Options lst)
{
    if (lst.size() < 2)
    {
        throw std::runtime_error(fmt::format("CSV parser need at least two headers"));
    }

    const char delimiter = ',';
    const char quote = '"';
    const char scape = '"';

    std::vector<std::string> headers;
    std::transform(lst.begin(),
                   lst.end(),
                   std::back_inserter(headers),
                   [](auto s) { return fmt::format("/{}", s); });

    return dsvParserFunction(name, endTokens, delimiter, quote, scape, headers);
}

} // namespace hlp
