/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
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

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_HEADER_UTILS_HPP
