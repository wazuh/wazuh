/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYNC_SESSION_WIRE_HPP
#define SYNC_SESSION_WIRE_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

/*
 * The wire contract for a whole stateful sync session crossing the agent's
 * local STREAM socket (`queue-sync`): sync_protocol writes the frame, the
 * HTTPS client's intake reads it. Both ends include this one header so the
 * layout can never drift apart silently.
 *
 * Frame layout (little-endian, the OS_SendSecureTCP convention):
 *   magic      4 bytes  "WZSY"
 *   id_len     4 bytes  session-id length (bounded by SESSION_ID_MAX_LENGTH)
 *   id         id_len   session-id bytes (see isValidSessionId for the charset)
 *   body_len   8 bytes  session body length (bounded by SYNC_FRAME_MAX_BODY)
 *   body       body_len session bytes
 *
 * The receiver then answers with one status byte, so the producer learns
 * whether the session was actually taken and can hold on to it if it was not.
 * Without it a full queue would look like a successful send.
 */

constexpr std::array<uint8_t, 4> SYNC_FRAME_MAGIC {'W', 'Z', 'S', 'Y'};

constexpr uint64_t SYNC_FRAME_MAX_BODY = 512ULL * 1024 * 1024;    ///< 512 MB body cap.

constexpr uint8_t SYNC_FRAME_ACCEPTED = 1;  ///< Queued for /stateful; the producer may forget it.
constexpr uint8_t SYNC_FRAME_REFUSED = 0;   ///< Not taken; the session is still the producer's.

/*
 * What a stateful sync session id is allowed to be.
 *
 * The id always crosses a process boundary before the intake sees it — over
 * the local STREAM socket, or through the C ABI — and it then goes straight
 * into the X-Session-Id request header the manager dedups retries on. An id
 * carrying CR, LF or any other control byte would split that header and let
 * the producer inject headers of its own, so the charset is pinned to what a
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

#endif // SYNC_SESSION_WIRE_HPP
