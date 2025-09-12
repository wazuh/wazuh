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

Mapper getMapper(bool parsed, std::string_view targetField)
{
    return [parsed, targetField](json::Json& event)
    {
        event.setBool(parsed, targetField);
    };
}

SemParser getTrueSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        return getMapper(true, targetField);
    };
}

SemParser getFalseSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed)
    {
        return getMapper(false, targetField);
    };
}

syntax::Parser getTrueSynParser()
{
    return syntax::parsers::literal("true", false);
}

syntax::Parser getFalseSynParser()
{
    return syntax::parsers::literal("false", false);
}
} // namespace
namespace hlp::parsers
{

Parser getBoolParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw std::runtime_error("bool parser doesn't accept parameters");
    }

    const auto trueSynP = getTrueSynParser();
    const auto falseSynP = getFalseSynParser();
    const auto trueSemP = params.targetField.empty() ? noSemParser() : getTrueSemParser(params.targetField);
    const auto falseSemP = params.targetField.empty() ? noSemParser() : getFalseSemParser(params.targetField);

    return [name = params.name, trueSynP, trueSemP, falseSynP, falseSemP](std::string_view txt)
    {
        const auto trueSynR = trueSynP(txt);
        if (trueSynR.success())
        {
            return abs::makeSuccess(SemToken {syntax::parsed(trueSynR, txt), trueSemP}, trueSynR.remaining());
        }

        const auto falseSynR = falseSynP(txt);
        if (falseSynR.success())
        {
            return abs::makeSuccess(SemToken {syntax::parsed(falseSynR, txt), falseSemP}, falseSynR.remaining());
        }

        return abs::makeFailure<ResultT>(txt, name);
    };
}
} // namespace hlp::parsers
