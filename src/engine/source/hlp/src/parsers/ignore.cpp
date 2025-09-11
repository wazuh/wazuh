#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace
{
using namespace hlp;
using namespace hlp::parser;

syntax::Parser getSynParser(const std::string& literal)
{
    return syntax::combinators::many1(syntax::parsers::literal(literal));
}
} // namespace

namespace hlp::parsers
{

Parser getIgnoreParser(const Params& params)
{
    if (params.options.size() != 1 || params.options[0].empty())
    {
        throw std::runtime_error("Ignore parser requires exactly one parameter,"
                                 " with the string to match");
    }

    if (!params.targetField.empty())
    {
        throw std::runtime_error("Ignore parser does not support targetField");
    }

    auto synP = getSynParser(params.options[0]);
    auto semP = noSemParser();

    return [synP, semP, name = params.name](std::string_view txt)
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
