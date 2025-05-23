#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <fmt/format.h>

#include "hlp.hpp"
#include "parse_field.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

size_t findNext(std::string_view input, size_t start, char target, char quote, char esc)
{
    bool inQuotes = false;

    for (size_t i = start; i < input.size(); ++i)
    {
        bool isQuote = input[i] == quote;
        bool isEscaped = (i > 0 && input[i - 1] == esc && esc != quote);
        bool isDoubleQuoteEscape = (quote == esc && i + 1 < input.size() && input[i] == quote && input[i + 1] == quote);

        if (isQuote && !isEscaped)
        {
            if (isDoubleQuoteEscape)
            {
                ++i; // skip escaped quote
            }
            else
            {
                inQuotes = !inQuotes;
            }
        }
        else if (input[i] == target && !inQuotes && !isEscaped)
        {
            return i;
        }
    }

    return std::string_view::npos;
}

void processKeyValue(
    json::Json& doc, std::string_view key, std::string_view value, char quote, char esc, char sep, char delim)
{
    // Check if the ending quote is escaped
    bool isEscapedQuoteAtEnd = value.size() >= 2 && value.back() == quote && value[value.size() - 2] == esc;

    // Checks if the value is enclosed in unescaped quotes
    bool isQuoted = (value.size() >= 2 && value.front() == quote && value.back() == quote && !isEscapedQuoteAtEnd);

    if (isQuoted)
    {
        value.remove_prefix(1);
        value.remove_suffix(1);
    }

    if (key.size() >= 2 && key.front() == quote && key.back() == quote)
    {
        key.remove_prefix(1), key.remove_suffix(1);
    }

    bool hasEscape = false;
    for (size_t i = 0; i + 1 < value.size(); ++i)
    {
        if (value[i] == esc
            && (value[i + 1] == quote || value[i + 1] == sep || value[i + 1] == delim || value[i + 1] == esc))
        {
            hasEscape = true;
            break;
        }
    }

    updateDoc(doc, fmt::format("/{}", key), value, hasEscape, std::string(1, esc), isQuoted);
}

bool validateKeyValue(std::string_view input,
                      size_t& pos,
                      std::string_view& key,
                      std::string_view& value,
                      char sep,
                      char delim,
                      char quote,
                      char esc)
{
    size_t sepPos = findNext(input, pos, sep, quote, esc);
    size_t delimBeforeSep = findNext(input, pos, delim, quote, esc);

    if (delimBeforeSep != std::string_view::npos && (sepPos == std::string_view::npos || delimBeforeSep < sepPos))
    {
        return false;
    }

    if (sepPos == std::string_view::npos || sepPos == pos)
    {
        return false;
    }

    key = input.substr(pos, sepPos - pos);
    pos = sepPos + 1;

    size_t delimPos = findNext(input, pos, delim, quote, esc);
    if (delimPos == std::string_view::npos)
    {
        value = input.substr(pos);
        pos = input.size();
    }
    else
    {
        value = input.substr(pos, delimPos - pos);
        pos = delimPos + 1;
    }

    return true;
}

Mapper getMapper(const json::Json& doc, std::string_view targetField)
{
    return [doc, targetField](json::Json& event)
    {
        event.set(targetField, doc);
    };
}

SemParser getSemParser(const std::string& targetField, char delim, char sep, char quote, char esc)
{
    return [=](std::string_view input)
    {
        json::Json doc {};
        size_t pos = 0;
        std::string_view key, value;

        while (pos < input.size() && validateKeyValue(input, pos, key, value, sep, delim, quote, esc))
        {
            processKeyValue(doc, key, value, quote, esc, sep, delim);
        }

        return targetField.empty() ? noMapper() : getMapper(doc, targetField);
    };
}

syntax::Parser getSynParser(char delim, char sep, char quote, char esc)
{
    return [=](std::string_view input) -> syntax::Result
    {
        if (input.empty())
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        size_t pos = 0;
        size_t lastValidPos = 0;
        bool parsedAny = false;
        std::string_view key, value;

        while (pos < input.size() && validateKeyValue(input, pos, key, value, sep, delim, quote, esc))
        {
            lastValidPos = pos;
            parsedAny = true;
        }

        if (!parsedAny)
        {
            return abs::makeFailure<syntax::ResultT>(input.substr(pos), {});
        }

        return abs::makeSuccess<syntax::ResultT>(std::move(input), input.substr(lastValidPos));
    };
}

} // namespace

namespace hlp::parsers
{

Parser getKVParser(const Params& params)
{
    if (params.options.size() != 4)
    {
        throw std::runtime_error(fmt::format("KV parser requires four parameters: separator, delimiter, quote "
                                             "character and escape character"));
    }

    for (const auto& opt : params.options)
    {
        if (opt.size() != 1)
        {
            throw std::runtime_error("KV parser: separator, delimiter, quote and escape must be single characters");
        }
    }

    const char sep = params.options[0][0];   // separator between key and value
    const char delim = params.options[1][0]; // delimiter between key-value pairs
    const char quote = params.options[2][0]; // quote character
    const char esc = params.options[3][0];   // escape character

    if (sep == delim)
    {
        throw std::runtime_error("KV parser: separator and delimiter must be different");
    }

    const auto targetField = params.targetField;

    const auto synP = getSynParser(delim, sep, quote, esc);
    const auto semP = getSemParser(targetField, delim, sep, quote, esc);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        auto parsed = syntax::parsed(synR, txt);
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}

} // namespace hlp::parsers
