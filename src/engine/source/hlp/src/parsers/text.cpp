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

} // namespace

namespace hlp::parsers
{
Parser getTextParser(const Params& params)
{
    if (params.stop.empty())
    {
        throw std::runtime_error(fmt::format("Text parser needs a stop string"));
    }

    if (!params.options.empty())
    {
        throw std::runtime_error("text parser doesn't accept parameters");
    }

    syntax::Parser synP =
        params.stop.front().empty() ? syntax::parsers::toEnd() : syntax::parsers::toEnd(params.stop.front());
    for (auto it = params.stop.begin() + 1; it != params.stop.end(); ++it)
    {
        using namespace syntax::combinators;
        auto next = it->empty() ? syntax::parsers::toEnd() : syntax::parsers::toEnd(*it);
        synP = synP | next;
    }

    const auto semP = params.targetField.empty() ? noSemParser() : getSemParser(params.targetField);

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
