/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_HEADER_UTILS_HPP
#define _REMOTED_HTTP_SERVER_HEADER_UTILS_HPP

#include <cctype>
#include <string>
#include <string_view>
#include <unordered_map>

namespace remoted::http
{

    /**
     * @brief Case-insensitive header lookup.
     *
     * HTTP header names are case-insensitive (RFC 7230 3.2), and RestinioHttpServer's
     * makeHttpRequest() (RestinioHttpServer.cpp) stores each header under whatever case RESTinio's
     * parser hands back for it -- a well-known field name (e.g. "Authorization", "Content-Type")
     * comes back canonicalized to its RFC spelling, NOT lowercased. Every reader of
     * HttpRequest::headers must look up this way rather than an exact-match `find()`: an
     * exact-match lookup happens to work only against a handcrafted test request that inserted an
     * already-lowercase key directly (never having gone through the real transport), which masks
     * the exact bug a real HTTP client would trip over the wire -- discovered via
     * enrollmentMtlsE2E_test.cpp's real-TLS test failing while its direct-dispatch sibling passed.
     *
     * @param headers   The request's header map, as delivered by the transport.
     * @param lowerName The header name to find, already lowercase.
     * @return The header's value, or an empty string if absent.
     */
    inline std::string headerValue(const std::unordered_map<std::string, std::string>& headers,
                                   std::string_view lowerName)
    {
        for (const auto& [name, value] : headers)
        {
            if (name.size() != lowerName.size())
            {
                continue;
            }
            bool equal = true;
            for (std::size_t i = 0; i < name.size(); ++i)
            {
                if (static_cast<char>(std::tolower(static_cast<unsigned char>(name[i]))) != lowerName[i])
                {
                    equal = false;
                    break;
                }
            }
            if (equal)
            {
                return value;
            }
        }
        return {};
    }

    /**
     * @brief ASCII case-insensitive comparison of two header values or tokens.
     *
     * HTTP token values (a content coding, a parameter name) are conventionally lowercase, but
     * nothing guarantees a peer sends them that way.
     */
    inline bool equalsIgnoreCase(std::string_view a, std::string_view b)
    {
        if (a.size() != b.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < a.size(); ++i)
        {
            if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            {
                return false;
            }
        }
        return true;
    }

    namespace detail
    {
        inline std::string_view trimBlanks(std::string_view text)
        {
            while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
            {
                text.remove_prefix(1);
            }
            while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
            {
                text.remove_suffix(1);
            }
            return text;
        }

        /// RFC 9110 12.4.2 qvalue (`0[.ddd]` or `1[.000]`): true only when it is well formed and not zero.
        inline bool isPositiveQValue(std::string_view value)
        {
            if (value.empty() || value.size() > 5 || (value[0] != '0' && value[0] != '1'))
            {
                return false;
            }
            if (value.size() == 1)
            {
                return value[0] == '1';
            }
            if (value[1] != '.')
            {
                return false;
            }
            bool positive = value[0] == '1';
            for (std::size_t i = 2; i < value.size(); ++i)
            {
                if (value[i] < '0' || value[i] > '9' || (value[0] == '1' && value[i] != '0'))
                {
                    return false;
                }
                positive = positive || value[i] != '0';
            }
            return positive;
        }
    } // namespace detail

    /**
     * @brief Whether an `Accept-Encoding` value offers the content coding @p token.
     *
     * Reduced to what agents send: a comma-separated list, the coding compared case-insensitively,
     * and a `q` weight where zero means "not acceptable". `*` and `identity` are deliberately not
     * interpreted, so a client has to name the coding to get it. A malformed weight reads as "not
     * offered": the failure direction is a plain response, which every client accepts.
     *
     * @param acceptEncoding The header's raw value (empty when absent).
     * @param token          The coding to look for, e.g. "zstd".
     */
    inline bool acceptsEncoding(std::string_view acceptEncoding, std::string_view token)
    {
        while (!acceptEncoding.empty())
        {
            const auto comma = acceptEncoding.find(',');
            auto member = detail::trimBlanks(acceptEncoding.substr(0, comma));
            acceptEncoding = comma == std::string_view::npos ? std::string_view {} : acceptEncoding.substr(comma + 1);

            const auto semicolon = member.find(';');
            if (!equalsIgnoreCase(detail::trimBlanks(member.substr(0, semicolon)), token))
            {
                continue;
            }

            auto parameters = semicolon == std::string_view::npos ? std::string_view {} : member.substr(semicolon + 1);
            while (!parameters.empty())
            {
                const auto next = parameters.find(';');
                const auto parameter = detail::trimBlanks(parameters.substr(0, next));
                parameters = next == std::string_view::npos ? std::string_view {} : parameters.substr(next + 1);

                const auto equals = parameter.find('=');
                if (equals != std::string_view::npos &&
                    equalsIgnoreCase(detail::trimBlanks(parameter.substr(0, equals)), "q"))
                {
                    return detail::isPositiveQValue(detail::trimBlanks(parameter.substr(equals + 1)));
                }
            }
            return true;
        }
        return false;
    }

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_HEADER_UTILS_HPP
