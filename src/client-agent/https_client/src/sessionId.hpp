/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_SESSION_ID_HPP
#define _HC_SESSION_ID_HPP

#include <algorithm>
#include <cstdint>
#include <string>

/*
 * What a stateful sync session id is allowed to be.
 *
 * The id always crosses a process boundary before we see it — over the local
 * STREAM intake, or through the C ABI — and it then goes straight into the
 * X-Session-Id request header the manager dedups retries on. An id carrying
 * CR, LF or any other control byte would split that header and let the
 * producer inject headers of its own, so the charset is pinned to what a
 * producer legitimately needs: UUIDs, hex digests and "<module>-<counter>"
 * shapes. Deliberately no locale-sensitive <cctype> here.
 */

constexpr uint32_t SESSION_ID_MAX_LENGTH = 256;

inline bool isValidSessionId(const std::string& sessionId)
{
    if (sessionId.empty() || sessionId.size() > SESSION_ID_MAX_LENGTH)
    {
        return false;
    }

    return std::all_of(sessionId.begin(),
                       sessionId.end(),
                       [](char character)
    {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'z') ||
               (character >= 'A' && character <= 'Z') || character == '-' ||
               character == '_' || character == '.';
    });
}

#endif // _HC_SESSION_ID_HPP
