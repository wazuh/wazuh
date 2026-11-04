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
#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>

namespace remoted::http
{

    namespace detail
    {
        /// ASCII case-insensitive equality against an already lowercase @p lower.
        inline bool equalsIgnoreCase(std::string_view text, std::string_view lower)
        {
            if (text.size() != lower.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < text.size(); ++i)
            {
                if (static_cast<char>(std::tolower(static_cast<unsigned char>(text[i]))) != lower[i])
                {
                    return false;
                }
            }
            return true;
        }
    } // namespace detail

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
            if (detail::equalsIgnoreCase(name, lowerName))
            {
                return value;
            }
        }
        return {};
    }

    namespace detail
    {
        inline std::string_view trimOws(std::string_view text)
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

        /// RFC 9110 12.4.2 qvalue. Sets @p positive when the weight is above zero.
        inline bool parseQValue(std::string_view text, bool& positive)
        {
            if (text.empty() || (text[0] != '0' && text[0] != '1'))
            {
                return false;
            }
            const char lead = text[0];
            text.remove_prefix(1);
            if (!text.empty())
            {
                if (text[0] != '.' || text.size() > 4)
                {
                    return false;
                }
                text.remove_prefix(1);
            }
            positive = lead == '1';
            for (const char c : text)
            {
                if (lead == '1' ? c != '0' : (c < '0' || c > '9'))
                {
                    return false;
                }
                positive = positive || c != '0';
            }
            return true;
        }
    } // namespace detail

    /**
     * @brief Whether an Accept-Encoding value offers zstd.
     *
     * True when at least one `zstd` element has a valid weight above zero and no `zstd` element has
     * a zero or invalid weight. Elements of any other coding (`gzip`, `identity`, `*`) are ignored.
     * Only the `q` parameter is accepted on a `zstd` element; any other parameter, a repeated `q` or
     * a malformed weight makes that element invalid.
     */
    inline bool acceptsZstd(std::string_view value)
    {
        bool offered = false;
        while (!value.empty())
        {
            const auto comma = value.find(',');
            std::string_view element = detail::trimOws(value.substr(0, comma));
            value = comma == std::string_view::npos ? std::string_view {} : value.substr(comma + 1);
            if (element.empty())
            {
                continue;
            }

            const auto semicolon = element.find(';');
            if (!detail::equalsIgnoreCase(detail::trimOws(element.substr(0, semicolon)), "zstd"))
            {
                continue;
            }

            bool positive = true;
            bool sawWeight = false;
            std::string_view params =
                semicolon == std::string_view::npos ? std::string_view {} : element.substr(semicolon + 1);
            while (!params.empty())
            {
                const auto next = params.find(';');
                const std::string_view param = detail::trimOws(params.substr(0, next));
                params = next == std::string_view::npos ? std::string_view {} : params.substr(next + 1);
                if (param.empty())
                {
                    continue;
                }

                const auto equals = param.find('=');
                if (equals == std::string_view::npos || sawWeight ||
                    !detail::equalsIgnoreCase(param.substr(0, equals), "q") ||
                    !detail::parseQValue(param.substr(equals + 1), positive))
                {
                    return false;
                }
                sawWeight = true;
            }

            if (!positive)
            {
                return false;
            }
            offered = true;
        }
        return offered;
    }

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_HEADER_UTILS_HPP
