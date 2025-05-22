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

void processKeyValue(
    json::Json& doc, std::string_view key, std::string_view value, char quote, char esc, char sep, char delim)
{
    bool isQuoted = false;
    bool hasEscape = false;

    // Check for escapes before cutting quotes
    for (size_t i = 0; i + 1 < value.size(); ++i)
    {
        if (value[i] == esc
            && (value[i + 1] == quote || value[i + 1] == sep || value[i + 1] == delim || value[i + 1] == esc))
        {
            hasEscape = true;
            break;
        }
    }

    // Check if it is enclosed in real (not escaped) quotes
    auto quoted = (value.size() >= 2 && value.front() == quote && value.back() == quote
                   && (value.size() < 2 || value[value.size() - 2] != esc));

    if (quoted)
    {
        value = value.substr(1, value.size() - 2);
        isQuoted = true;
    }

    // The same applies to the key
    if (key.size() >= 2 && key.front() == quote && key.back() == quote)
    {
        key = key.substr(1, key.size() - 2);
    }

    updateDoc(doc, fmt::format("/{}", key), value, hasEscape, std::string(1, esc), isQuoted);
}

size_t findNext(std::string_view input, size_t start, char ch, char quote, char esc)
{
    bool inQuotes = false;

    auto isEscaped = [quote, esc, input](size_t i)
    {
        return i > 0 && input[i - 1] == esc && esc != quote;
    };

    auto isDoubleQuoteEscape = [quote, esc, input](size_t i)
    {
        return quote == esc && i + 1 < input.size() && input[i] == quote && input[i + 1] == quote;
    };

    auto isQuoteChar = [input, quote](size_t i)
    {
        return input[i] == quote;
    };

    for (size_t i = start; i < input.size(); ++i)
    {
        if (isQuoteChar(i))
        {
            if (isDoubleQuoteEscape(i))
            {
                ++i;
                continue;
            }

            if (quote == esc || !isEscaped(i))
            {
                inQuotes = !inQuotes;
                continue;
            }
        }

        if (input[i] == ch && !inQuotes)
        {
            if (isEscaped(i))
            {
                continue;
            }

            return i;
        }
    }

    return std::string_view::npos;
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
        size_t len = input.size();

        while (pos < len)
        {
            size_t sepPos = findNext(input, pos, sep, quote, esc);
            size_t delimBeforeSep = findNext(input, pos, delim, quote, esc);

            // Validate that there is no delimiter before a separator
            if (delimBeforeSep != std::string_view::npos
                && (sepPos == std::string_view::npos || delimBeforeSep < sepPos))
            {
                break;
            }

            if (sepPos == std::string_view::npos)
            {
                pos = (pos == 0) ? pos : pos - 1;
                break;
            }

            // Validate non-empty key
            auto key = input.substr(pos, sepPos - pos);
            if (key.empty())
            {
                break;
            }

            pos = sepPos + 1;

            // Search delimiter to find value
            auto delimPos = findNext(input, pos, delim, quote, esc);
            std::string_view rawVal;
            if (delimPos == std::string_view::npos)
            {
                rawVal = input.substr(pos);
                pos = len;
            }
            else
            {
                rawVal = input.substr(pos, delimPos - pos);
                pos = delimPos + 1;
            }

            processKeyValue(doc, key, rawVal, quote, esc, sep, delim);
        }

        if (targetField.empty())
        {
            return noMapper();
        }

        return getMapper(doc, targetField);
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

        while (pos < input.size())
        {
            auto sepPos = findNext(input, pos, sep, quote, esc);
            auto delimBeforeSep = findNext(input, pos, delim, quote, esc);

            // Validate that there is no delimiter before a separator
            if (delimBeforeSep != std::string_view::npos
                && (sepPos == std::string_view::npos || delimBeforeSep < sepPos))
            {
                break;
            }

            if (sepPos == std::string_view::npos)
            {
                pos == 0 ? pos : pos - 1;
                break;
            }

            // Validate non-empty key
            auto key = input.substr(pos, sepPos - pos);
            if (key.empty())
            {
                break;
            }

            pos = sepPos + 1;

            // Search delimiter to find value
            auto delimPos = findNext(input, pos, delim, quote, esc);
            if (delimPos == std::string_view::npos)
            {
                input.substr(pos);
                lastValidPos = input.size();
                pos = input.size();
                parsedAny = true;
                break;
            }
            else
            {
                input.substr(pos, delimPos - pos);
                lastValidPos = delimPos;
                pos = delimPos + 1;
            }

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

    if (params.options[0].size() != 1 || params.options[1].size() != 1 || params.options[2].size() != 1
        || params.options[3].size() != 1)
    {
        throw std::runtime_error(fmt::format("KV parser: separator, delimiter, quote and escape must be single "
                                             "characters"));
    }

    const char sep = params.options[0][0];   // separator between key and value
    const char delim = params.options[1][0]; // delimiter between key-value pairs
    const char quote = params.options[2][0]; // quote character
    const char esc = params.options[3][0];   // escape character

    // Check if the arguments of the parser are valid
    if (sep == delim)
    {
        throw std::runtime_error(fmt::format("KV parser: separator and delimiter must be different"));
    }

    const auto targetField = params.targetField.empty() ? "" : params.targetField;

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
