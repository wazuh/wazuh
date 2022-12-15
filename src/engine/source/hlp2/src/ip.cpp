
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
parsec::Parser<json::Json> getIPParser(std::string name, Stop endTokens, Options lst)
{
    if (endTokens.empty())
    {
        throw std::runtime_error("IP parser needs a stop string");
    }

    if (lst.size() > 0)
    {
        throw std::runtime_error("The IP parser does not accept any argument");
    }

    return [endTokens, name](std::string_view text, size_t index)
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
            return parsec::makeSuccess<json::Json>(std::move(doc), pos);
        }
        else if (inet_pton(AF_INET6, addr.c_str(), &ipv6))
        {
            doc.setString(addr);
            return parsec::makeSuccess<json::Json>(std::move(doc), pos);
        }

        return parsec::makeError<json::Json>(
            fmt::format("{}: Expected IPv4 or IPv6", name), index);
    };
}
} // namespace hlp
