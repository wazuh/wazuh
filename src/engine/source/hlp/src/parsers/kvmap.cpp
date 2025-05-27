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
        size_t start = 0;

        // Search for target respecting quotes and escapes
        auto findNext = [&](std::string_view text, size_t pos, char target) -> size_t
        {
            bool inQuotes = false;
            for (size_t i = pos; i < text.size(); ++i)
            {
                bool isQuote = text[i] == quote;
                bool isEscaped = (i > 0 && text[i - 1] == esc && esc != quote);
                bool isDoubleQuoteEscape =
                    (quote == esc && i + 1 < text.size() && text[i] == quote && text[i + 1] == quote);

                if (isQuote && !isEscaped)
                {
                    if (isDoubleQuoteEscape)
                    {
                        ++i;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (text[i] == target && !inQuotes && !isEscaped)
                {
                    return i;
                }
            }
            return std::string_view::npos;
        };

        // Process and normalize key/value before inserting into JSON
        auto processKeyValue = [&](std::string_view rawKey, std::string_view rawValue)
        {
            // Strip outer quotes if they exist
            bool escapedEndQuote =
                rawValue.size() >= 2 && rawValue.back() == quote && rawValue[rawValue.size() - 2] == esc;
            bool quoted =
                (rawValue.size() >= 2 && rawValue.front() == quote && rawValue.back() == quote && !escapedEndQuote);
            if (quoted)
            {
                rawValue.remove_prefix(1), rawValue.remove_suffix(1);
            }

            if (rawKey.size() >= 2 && rawKey.front() == quote && rawKey.back() == quote)
            {
                rawKey.remove_prefix(1), rawKey.remove_suffix(1);
            }

            // Detect internal escapes
            bool hasEscape = false;
            for (size_t i = 0; i + 1 < rawValue.size(); ++i)
            {
                char c = rawValue[i], n = rawValue[i + 1];
                if (c == esc && (n == quote || n == sep || n == delim || n == esc))
                {
                    hasEscape = true;
                    break;
                }
            }

            updateDoc(doc, fmt::format("/{}", rawKey), rawValue, hasEscape, std::string(1, esc), quoted);
        };

        while (start < input.size())
        {
            // key–value separation is sought
            size_t sepPos = findNext(input, start, sep);
            if (sepPos == std::string_view::npos)
                break;

            std::string_view key = input.substr(start, sepPos - start);
            size_t valStart = sepPos + 1;

            // The end of the value is sought
            size_t delimPos = findNext(input, valStart, delim);
            std::string_view value = (delimPos == std::string_view::npos) ? input.substr(valStart)
                                                                          : input.substr(valStart, delimPos - valStart);

            processKeyValue(key, value);

            if (delimPos == std::string_view::npos)
            {
                break;
            }
            start = delimPos + 1;
        }

        return targetField.empty() ? noMapper() : getMapper(doc, targetField);
    };
}

syntax::Parser getSynParser(char delim, char sep, char quote, char esc)
{
    return [=](std::string_view input) -> syntax::Result
    {
        if (input.empty())
            return abs::makeFailure<syntax::ResultT>(input, {});

        size_t pos = 0;
        size_t lastValidPos = 0;
        bool parsedAny = false;
        std::string_view key, value;
        bool inQuotes = false;

        // Search for target respecting quotes and escapes
        auto findNext = [&](std::string_view text, size_t start, char target) -> size_t
        {
            for (size_t i = start; i < text.size(); ++i)
            {
                bool isEscaped = (i > 0 && text[i - 1] == esc && esc != quote);
                bool isQuote = (text[i] == quote) && !isEscaped;
                bool isDoubleQuoteEscape =
                    (quote == esc && i + 1 < text.size() && text[i] == quote && text[i + 1] == quote);

                if (isQuote)
                {
                    if (isDoubleQuoteEscape)
                    {
                        ++i;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (text[i] == target && !inQuotes && !isEscaped)
                {
                    return i;
                }
            }
            return std::string_view::npos;
        };

        // Validates a key=value pair using findNext
        auto validateKeyValue =
            [&](std::string_view text, size_t& pos, std::string_view& key, std::string_view& value) -> bool
        {
            size_t sepPos = findNext(text, pos, sep);
            size_t delimPos = findNext(text, pos, delim);
            if (delimPos != std::string_view::npos && (sepPos == std::string_view::npos || delimPos < sepPos))
            {
                return false;
            }

            if (sepPos == std::string_view::npos || sepPos == pos)
            {
                return false;
            }

            key = text.substr(pos, sepPos - pos);
            pos = sepPos + 1;

            if (delimPos == std::string_view::npos)
            {
                // If the quotes were not closed, it fails
                if (inQuotes)
                {
                    return false;
                }
                value = text.substr(pos);
                pos = text.size();
            }
            else
            {
                value = text.substr(pos, delimPos - pos);
                pos = delimPos + 1;
            }

            return true;
        };

        while (pos < input.size() && validateKeyValue(input, pos, key, value))
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
