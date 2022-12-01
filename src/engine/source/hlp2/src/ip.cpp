
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
parsec::Parser<json::Json> getIPParser(Stop endTokens, Options lst)
{
    if (endTokens.empty())
    {
        throw std::invalid_argument(fmt::format("IP parser needs a stop string"));
    }

    return [endTokens](std::string_view text, size_t index)
    {
        struct in_addr ip;
        struct in6_addr ipv6;

        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);
        auto pos = fp.size() + index;

        // copy can be slow
        std::string addr(fp.data(), fp.size());
        json::Json doc;

        if (inet_pton(AF_INET, addr.c_str(), &ip))
        {
            doc.setString(addr);
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }
        else if (inet_pton(AF_INET6, addr.c_str(), &ipv6))
        {
            doc.setString(addr);
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }

        return parsec::makeError<json::Json>(
            fmt::format("IP parser is unable to parse '{}' as IPv4 or IPv6", addr),
            text,
            index);
    };
}
} // namespace hlp
