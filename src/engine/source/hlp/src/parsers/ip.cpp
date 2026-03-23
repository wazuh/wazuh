#include <stdexcept>
#include <string>
#include <string_view>
#include <sys/types.h>

#include <arpa/inet.h>
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
    return [targetField](std::string_view parsed) -> std::variant<Mapper, base::Error>
    {
        struct in_addr ip;
        struct in6_addr ip6;

        if (!inet_pton(AF_INET, std::string(parsed).c_str(), &ip)
            && !inet_pton(AF_INET6, std::string(parsed).c_str(), &ip6))
        {
            return base::Error {"Invalid IPv4 or IPv6 address"};
        }

        if (targetField.empty())
        {
            return noMapper();
        }

        return getMapper(parsed, targetField);
    };
}

syntax::Parser getSynParser()
{
    using namespace syntax::combinators;

    // IPv4
    auto digits = times(syntax::parsers::digit(), 1, 3);
    auto dot = syntax::parsers::char_('.');
    auto part = digits & dot;
    auto ipv4 = repeat(part, 3) & digits;

    // IPv6
    auto hexes = times(syntax::parsers::hex(), 0, 4);
    auto colon = syntax::parsers::char_(':');
    auto part6 = hexes & colon;
    auto ipv6 = times(part6, 2, 7) & hexes;

    // Mixed
    auto mixed = times(part6, 2, 6) & ipv4;

    return ipv4 | mixed | ipv6;
}

} // namespace

namespace hlp::parsers
{
Parser getIPParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw std::runtime_error("The IP parser does not accept any argument");
    }

    syntax::Parser synP = getSynParser();

    auto target = params.targetField.empty() ? "" : params.targetField;
    auto semP = getSemParser(target);

    return [name = params.name, synP, semP](std::string_view txt)
    {
        auto synR = synP(txt);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }
        else
        {
            auto parsed = syntax::parsed(synR, txt);
            return abs::makeSuccess(SemToken {parsed, semP}, synR.remaining());
        }
    };
}
} // namespace hlp::parsers
