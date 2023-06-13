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

SemParser getSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        return getMapper(parsed, targetField);
    };
}

syntax::Parser getSynParser()
{
    return syntax::combinators::many1(syntax::parsers::alnum());
}
} // namespace

namespace hlp::parsers
{
Parser getAlphanumericParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw std::runtime_error("alphanumeric parser doesn't accept parameters");
    }

    const auto synP = getSynParser();
    const auto semP =
        params.targetField.empty() ? noSemParser() : getSemParser(params.targetField);

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
