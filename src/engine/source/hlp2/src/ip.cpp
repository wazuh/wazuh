
#include <optional>
#include <string>
#include <sys/types.h>
#include <vector>

#include <arpa/inet.h>
#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace hlp
{
parsec::MergeableParser<jFnList> getIPParser(const hlp::ParserSpec& spec)
{

    if (spec.endTokens().empty())
    {
        throw std::runtime_error("IP parser needs a stop string");
    }

    if (spec.args().size() > 0)
    {
        throw std::runtime_error("The IP parser does not accept any argument");
    }

    /******************************************************
      Stege 4: Define the semantic action
     ******************************************************/
    auto semanticProcessor = [spec](jFnList& result,
                                    const std::deque<std::string_view>& tokens,
                                    const parsec::ParserState& state) -> std::pair<bool, std::optional<parsec::TraceP>>
    {
        // tokens.size() == 1 because the parser is a single token parser
        auto srcip = std::string(tokens.front());

        // Check if the IP is valid
        struct in_addr ipv4;
        struct in6_addr ipv6;

        // Check IPv4 and IPv6
        if (inet_pton(AF_INET, srcip.c_str(), &ipv4) || inet_pton(AF_INET6, srcip.c_str(), &ipv6))
        {
            if (spec.capture())
            {
                result.push_back([targetField = spec.targetField(), value = std::move(srcip)](json::Json& json)
                                 { json.setString(value, targetField); });
            }
            return {true, std::nullopt};
        }

        if (state.isTraceEnabled())
        {
            auto trace = fmt::format("[failed] {} -> Invalid IP address: '{}'", spec.name(), srcip);
            auto offset = srcip.data() - state.getData().data();
            return {false, parsec::TraceP(trace, offset)};
        }

        return {false, std::nullopt};
    };

    // Sintactic action
    return [semanticProcessor, spec](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        /******************************************************
         Stege 1: Preprocess: Check EOF and endtoken
        ******************************************************/
        auto preResult = internal::preProcess<jFnList>(state, spec.endTokens());
        if (std::holds_alternative<parsec::MergeableResultP<jFnList>>(preResult))
        {
            return std::get<parsec::MergeableResultP<jFnList>>(preResult);
        }

        /******************************************************
         Stege 2: Sintactic action
        ******************************************************/
        auto result = parsec::MergeableResultP<jFnList>::failure(state);
        auto ipCandidate = std::get<std::string_view>(preResult);

        // Check long IP
        constexpr std::size_t IPv6Length = std::char_traits<char>::length("fd7a:115c:a1e0:ab12:4843:cd96:626d:1730");
        if (ipCandidate.size() > IPv6Length)
        {
            if (state.isTraceEnabled())
            {
                auto msg = fmt::format("[failure] {} -> IP '{}' is too long", spec.name(), ipCandidate);
                result.concatenateTraces(parsec::TraceP(msg, state.getOffset()));
            }
            return result;
        }

        /******************************************************
         Stege 3: Prepare the result with the semantic action
        ******************************************************/
        parsec::Mergeable<jFnList> mergeable {.m_semanticProcessor = semanticProcessor, .m_tokens = {ipCandidate}};
        result.setSuccess(state.advance(ipCandidate.size()), std::move(mergeable));

        return result;
    };
}
} // namespace hlp
