#include <hlp/parsec.hpp>
#include <string>
#include <sys/types.h>
#include <arpa/inet.h>
#include <json/json.hpp>
#include <optional>
#include <vector>
#include "fmt/format.h"

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

namespace hlp
{
parsec::Parser<json::Json> getIPParser(Stop str, Options lst)
{
    if (!str.has_value())
    {
        throw std::invalid_argument(fmt::format("IP parser needs a stop string"));
    }

    return [str](std::string_view text, size_t index)
    {
        struct in_addr ip;
        struct in6_addr ipv6;


        size_t pos = text.size();
        std::string_view fp = text;
        if (str.has_value() && ! str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }

        // copy can be slow
        auto addr = std::string { fp};
        json::Json doc;

        if (inet_pton(AF_INET, addr.c_str(), &ip))
        {
            doc.setString(fp.data());
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }
        else if (inet_pton(AF_INET6, addr.c_str(), &ipv6))
        {
            doc.setString(fp.data());
            return parsec::makeSuccess<json::Json>(doc, text, pos);
        }

        return parsec::makeError<json::Json>(
            fmt::format("IP parser is unable to parse '{}' as IPv4 or IPv6", addr),
            text,
            index);
    };
}
}