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

SemParser getSemParser(json::Json&& doc, const std::string& targetField)
{
    return [targetField, doc](std::string_view)
    {
        return getMapper(doc, targetField);
    };
}

syntax::Parser getSynParser(char separator, char quote, char escape, bool requireSeparator)
{
    // Capture parameters and return a parsing lambda
    return [=](std::string_view input) -> syntax::Result
    {
        if (input.empty())
        {
            // Parsing fails if input is empty
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        size_t i = 0;         // Current position in the input
        size_t start = 0;     // Start of the current token
        bool inQuote = false; // Whether we're currently inside a quoted section

        // === Predicates ===

        // Returns the character at position i + offset, or '\0' if out of bounds
        const auto at = [&](size_t offset = 0) -> char
        {
            return i + offset < input.size() ? input[i + offset] : '\0';
        };

        // Checks if the current character matches the given one
        const auto match = [&](char c) -> bool
        {
            return at() == c;
        };

        // Returns true if the current character is the escape character and the next matches `target`
        const auto canEscape = [&](char target) -> bool
        {
            return match(escape) && at(1) == target;
        };

        // === Advancing the position ===

        // Moves forward n characters (default is 1)
        const auto skip = [&](size_t n = 1)
        {
            i += n;
        };

        // === Token processing logic ===

        // Processes characters when inside a quoted string
        const auto processQuote = [&]()
        {
            if (canEscape(quote))
            {
                // Escaped quote: skip both escape and quote characters
                skip(2);
                return;
            }
            if (match(quote))
            {
                // Closing quote: exit quoted mode
                inQuote = false;
                skip();
                return;
            }
            // Regular character inside quote
            skip();
        };

        // Processes characters when outside quotes
        const auto processUnquoted = [&]() -> std::optional<syntax::Result>
        {
            if (canEscape(separator))
            {
                // Escaped separator: skip both escape and separator characters
                skip(2);
                return std::nullopt;
            }
            if (match(quote))
            {
                // Enter quoted mode
                inQuote = true;
                skip();
                return std::nullopt;
            }
            if (match(separator))
            {
                // Token ends here: return it along with the remaining string
                auto token = input.substr(start, i - start);
                auto rest = input.substr(i + 1);
                return abs::makeSuccess<syntax::ResultT>(std::move(token), rest);
            }
            // Regular unquoted character
            skip();
            return std::nullopt;
        };

        // === Main loop ===
        while (i < input.size())
        {
            if (inQuote)
            {
                processQuote();
            }
            else if (auto res = processUnquoted(); res)
            {
                // Token successfully extracted
                return *res;
            }
        }

        // === Finalization ===
        if (inQuote || (requireSeparator))
        {
            // If we're still inside a quote, or a separator was required but not found, fail
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        // Return final token (no separator found, or not required)
        return abs::makeSuccess<syntax::ResultT>(input.substr(start, i - start), input.substr(i));
    };
}

std::tuple<std::string_view, bool, bool> processToken(std::string_view token, char delim, char quote, char esc)
{
    bool isQuoted = token.size() >= 2 && token.front() == quote && token.back() == quote;
    bool isEscaped = false;

    if (isQuoted)
    {
        token.remove_prefix(1);
        token.remove_suffix(1);
    }

    // Check if value contains escaped characters
    size_t escPos = token.find(esc);
    while (escPos != std::string_view::npos)
    {
        if (escPos + 1 < token.size() && (token[escPos + 1] == quote || token[escPos + 1] == delim))
        {
            isEscaped = true;
            break;
        }
        escPos = token.find(esc, escPos + 1);
    }

    return {token, isQuoted, isEscaped};
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

    return [sep, delim, quote, esc, name = params.name, targetField](std::string_view txt)
    {
        std::vector<std::string> tokens;
        std::vector<size_t> tokenOffsets;

        std::string_view rest = txt;
        auto parser = getSynParser(sep, quote, esc, true);
        bool expectKey = true;

        size_t parsedPos = 0;

        while (!rest.empty())
        {
            auto result = parser(rest);
            if (result.failure())
            {
                // Fail if a parsing step failed
                size_t failureOffset = parsedPos == 0 ? 0 : parsedPos - 1;
                return abs::makeFailure<ResultT>(txt.substr(failureOffset), name);
            }

            auto token = std::string(result.value());
            tokens.push_back(token);
            tokenOffsets.push_back(parsedPos);

            size_t consumed = rest.size() - result.remaining().size();
            parsedPos += consumed;
            rest = result.remaining();

            // Switch delimiter depending on expected type (key or value)
            if (!rest.empty())
            {
                parser = getSynParser(expectKey ? delim : sep, quote, esc, !expectKey);
            }

            expectKey = !expectKey;

            // If at the end of input, add empty value for null-pair keys
            if (rest.empty())
            {
                if (!expectKey || txt.back() == delim)
                {
                    tokens.push_back("");
                    tokenOffsets.push_back(parsedPos - 1);
                    break;
                }
            }
        }

        // No fields were extracted
        if (tokens.empty())
        {
            return abs::makeFailure<ResultT>(txt, name);
        }

        // Unmatched key-value pairs (odd number of tokens)
        if (tokens.size() % 2 != 0)
        {
            if (tokens.size() < 2)
            {
                return abs::makeFailure<ResultT>(txt, name);
            }

            return abs::makeFailure<ResultT>(txt.substr(tokenOffsets[tokens.size() - 1]), name);
        }

        // Input not fully consumed
        if (parsedPos != txt.size())
        {
            return abs::makeFailure<ResultT>(txt.substr(parsedPos), name);
        }

        json::Json doc {};

        for (size_t i = 0; i < tokens.size(); i += 2)
        {
            auto [key, keyQuoted, keyEscaped] = processToken(tokens[i], delim, quote, esc);
            auto [val, valQuoted, valEscaped] = processToken(tokens[i + 1], delim, quote, esc);

            if (key.empty())
            {
                // Fail on empty key
                return abs::makeFailure<ResultT>(txt.substr(tokenOffsets[i]), name);
            }

            updateDoc(doc, fmt::format("/{}", key), val, valEscaped, std::string_view {&esc, 1}, valQuoted);
        }

        const auto semP = targetField.empty() ? noSemParser() : getSemParser(std::move(doc), targetField);
        return abs::makeSuccess<ResultT>(SemToken {txt.substr(0, parsedPos), semP}, rest);
    };
}

} // namespace hlp::parsers
