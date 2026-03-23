#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include "hlp.hpp"
#include "number.hpp"
#include "parse_field.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(const json::Json& doc, std::string_view targetField)
{
    return [doc, targetField](json::Json& event)
    {
        event.set(targetField, doc);
    };
}

SemParser getSemParser(json::Json&& doc, const std::string& targetField)
{
    return [targetField, doc](std::string_view)
    {
        return getMapper(doc, targetField);
    };
}

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
inline Parser dsvParserFunction(std::string name,
                                Stop endTokens,
                                const char delimiterChar,
                                const char quoteChar,
                                const char escapeChar,
                                std::vector<std::string> headers,
                                const std::string& targetField)
{
    if (endTokens.empty())
    {
        throw std::runtime_error(fmt::format("CSV/DSV parser needs a stop string"));
    }

    const auto toStopP = syntax::parsers::toEnd(endTokens);

    return [toStopP, target = targetField, delimiterChar, quoteChar, headers, escapeChar, name](std::string_view txt)
    {
        auto synR = toStopP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        const auto parsed = syntax::parsed(synR, txt);
        const auto fieldNotFound = "No fields found";

        std::size_t start {0};

        json::Json doc {};
        auto i = 0;

        while (start <= parsed.size() && i < headers.size())
        {
            auto remaining = parsed.substr(start, parsed.size() - start);
            auto field = getField(remaining, delimiterChar, quoteChar, escapeChar, true);

            if (!field.has_value())
            {
                break;
            }

            auto fValue = field.value();

            auto v = remaining.substr(fValue.start(), fValue.len());
            updateDoc(doc, headers[i], v, fValue.isEscaped(), std::string_view {&escapeChar, 1}, fValue.isQuoted());

            start += fValue.end() + 1;
            i++;
        }

        // If start is 0, it means no fields were found
        if (start == 0)
        {
            return abs::makeFailure<ResultT>(fieldNotFound, name);
        }

        if (headers.size() != i)
        {
            return abs::makeFailure<ResultT>(txt.substr(start - 1), name);
        }

        if (start - 1 != parsed.size())
        {
            return abs::makeFailure<ResultT>(txt.substr(start - 1), name);
        }

        SemParser semP;
        if (target.empty())
        {
            semP = noSemParser();
        }
        else
        {
            semP = getSemParser(std::move(doc), target);
        }
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}
} // namespace

namespace hlp::parsers
{
Parser getDSVParser(const Params& params)
{
    if (params.options.size() < 5)
    {
        throw std::runtime_error(fmt::format("Need at least five options: delim, quote, "
                                             "escape characters and two headers"));
    }
    else if (params.options[0].size() != 1 || params.options[1].size() != 1 || params.options[2].size() != 1)
    {
        throw std::runtime_error(fmt::format("Delim, quote and escape characters must be single characters"));
    }

    const char delimiter = params.options[0][0];
    const char quote = params.options[1][0];
    const char scape = params.options[2][0];

    std::vector<std::string> headers;
    std::transform(std::next(params.options.begin(), 3),
                   params.options.end(),
                   std::back_inserter(headers),
                   [](auto s) { return fmt::format("/{}", s); });

    return dsvParserFunction(params.name, params.stop, delimiter, quote, scape, headers, params.targetField);
}

Parser getCSVParser(const Params& params)
{
    if (params.options.size() < 2)
    {
        throw std::runtime_error(fmt::format("CSV parser need at least two headers"));
    }

    const char delimiter = ',';
    const char quote = '"';
    const char scape = '"';

    std::vector<std::string> headers;
    std::transform(params.options.begin(),
                   params.options.end(),
                   std::back_inserter(headers),
                   [](auto s) { return fmt::format("/{}", s); });

    return dsvParserFunction(params.name, params.stop, delimiter, quote, scape, headers, params.targetField);
}

} // namespace hlp::parsers
