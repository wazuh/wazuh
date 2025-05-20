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

Mapper getMapper(std::string_view parsed, const std::string& targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.setString(parsed, targetField);
    };
}

SemParser getSemParser(std::string_view parsed, const Mapper& mapper)
{
    return [parsed, mapper](std::string_view)
    {
        return mapper;
    };
}

syntax::Parser getSynParser(const std::string& literal)
{
    return syntax::parsers::literal(literal);
}
} // namespace

namespace hlp::parsers
{

Parser getLiteralParser(const Params& params)
{
    if (params.options.size() != 1)
    {
        throw(std::runtime_error("Literal parser requires exactly one option with the literal to parse"));
    }

    const auto& literal = params.options[0];
    const auto synP = getSynParser(literal);
    const auto mapper = params.targetField.empty() ? noMapper() : getMapper(literal, params.targetField);
    const auto semP = getSemParser(literal, mapper);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }
        else
        {
            return abs::makeSuccess(SemToken {syntax::parsed(synR, txt), semP}, synR.remaining());
        }
    };
}
} // namespace hlp::parsers
