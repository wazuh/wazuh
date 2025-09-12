#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

Mapper getMapper(const std::string& parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.setString(parsed, targetField);
    };
}

SemParser getSemParser(const std::string& targetField, char escape)
{
    return [targetField, escape](std::string_view parsed)
    {
        std::string tr(parsed.begin() + 1, parsed.end() - 1);
        tr.erase(std::remove(tr.begin(), tr.end(), escape), tr.end());
        return getMapper(tr, targetField);
    };
}

syntax::Parser getSynParser(char quote, char escape)
{
    return [quote, escape](std::string_view input)
    {
        if (input.empty())
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        if (input[0] != quote)
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        bool checkEscape = false;
        bool closed = false;
        auto it = input.begin() + 1;
        for (; it < input.end(); ++it)
        {
            if (checkEscape)
            {
                if (*it != quote && *it != escape)
                {
                    return abs::makeFailure<syntax::ResultT>(input, {});
                }
                checkEscape = false;
                continue;
            }
            else if (*it == escape)
            {
                checkEscape = true;
                continue;
            }
            else if (*it == quote)
            {
                ++it;
                closed = true;
                break;
            }
        }

        if (closed)
        {
            return abs::makeSuccess<syntax::ResultT>(input.substr(it - input.begin()));
        }
        else
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }
    };
}

} // namespace
namespace hlp::parsers
{

Parser getQuotedParser(const Params& params)
{
    if (params.options.size() > 2)
    {
        throw std::runtime_error("Quoted parser requires 0, 1 or 2 parameters."
                                 " The first parameter is the quote character, the "
                                 "second is the escape character");
    }
    else if (!params.options.empty() && params.options[0].size() != 1)
    {
        throw std::runtime_error("Quoted parser requires a single character "
                                 "as delimiter. Got: "
                                 + params.options[0]);
    }
    else if (params.options.size() > 1 && params.options[1].size() != 1)
    {
        throw std::runtime_error("Quoted parser requires a single character "
                                 "as escape character. Got: "
                                 + params.options[1]);
    }

    // Default values for quote and escape characters
    char quoteChar = params.options.size() > 0 ? params.options[0][0] : '"';
    char escapeChar = params.options.size() > 1 ? params.options[1][0] : '\\';

    if (quoteChar == escapeChar)
    {
        throw std::runtime_error("Quoted parser requires different characters "
                                 "for quote and escape. Got: "
                                 + params.options[0]);
    }

    const auto synP = getSynParser(quoteChar, escapeChar);
    const auto semP = params.targetField.empty() ? noSemParser() : getSemParser(params.targetField, escapeChar);

    // The parser
    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        const auto parsed = syntax::parsed(synR, txt);
        return abs::makeSuccess<ResultT>(SemToken {parsed, semP}, synR.remaining());
    };
}
} // namespace hlp::parsers
