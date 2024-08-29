#include <optional>
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

Mapper getMapper(std::string_view parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.setString(parsed, targetField);
    };
}

SemParser getSemParser(const std::string& targetField, const std::string& startToken, const std::string& endToken)
{
    return [targetField, startToken, endToken](std::string_view parsed)
    {
        auto between = parsed.substr(startToken.size(), parsed.size() - startToken.size() - endToken.size());
        return getMapper(between, targetField);
    };
}

syntax::Parser getSynParser(const std::string& startToken, const std::string& endToken)
{
    return [startToken, endToken](std::string_view input) -> syntax::Result
    {
        if (input.substr(0, startToken.size()) != startToken)
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        auto endPos = input.find(endToken, startToken.size());
        if (endPos == std::string_view::npos)
        {
            return abs::makeFailure<syntax::ResultT>(input, {});
        }

        return abs::makeSuccess<syntax::ResultT>(input.substr(endPos + endToken.size()));
    };
}
} // namespace

namespace hlp::parsers
{

Parser getBetweenParser(const Params& params)
{
    if (params.options.size() != 2)
    {
        throw std::runtime_error("between parser requires exactly two parameters,"
                                 " start and end substrings");
    }
    // check empty strings
    if (params.options[0].empty() && params.options[1].empty())
    {
        throw std::runtime_error("between parser requires non-empty start and end substrings");
    }

    const auto start = params.options[0];
    const auto end = params.options[1];

    const auto synP = getSynParser(start, end);
    const auto semP = params.targetField.empty() ? noSemParser() : getSemParser(params.targetField, start, end);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }

        return abs::makeSuccess(SemToken {syntax::parsed(synR, txt), semP}, synR.remaining());
    };
}
} // namespace hlp::parsers
