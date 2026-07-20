/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_SYNC_FRAME_HPP
#define _HC_SYNC_FRAME_HPP

#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>

/*
 * Framing for a whole stateful sync session over a reliable, ordered STREAM
 * transport (a local Unix socket). Unlike the legacy DGRAM path there is no
 * 64 KB per-message cap: one session is one frame, and the body is STREAMED
 * (never held whole in memory).
 *
 * Wire layout (little-endian, the OS_SendSecureTCP convention):
 *   magic      4 bytes  "WZSY"
 *   id_len     4 bytes  session-id length (bounded)
 *   id         id_len   session-id bytes
 *   body_len   8 bytes  session body length
 *   body       body_len session bytes (streamed)
 *
 * The transport is abstracted as read/write callbacks so the framing is unit
 * tested without any socket; the socket component supplies fd-backed ones.
 */

/// Reads up to n bytes: returns >0 bytes read, 0 on EOF, <0 on error.
using SyncReadFn = std::function<long(void* buffer, size_t n)>;
/// Writes up to n bytes: returns >0 bytes written, <0 on error.
using SyncWriteFn = std::function<long(const void* buffer, size_t n)>;

enum class SyncFrameResult
{
    Ok,
    Truncated,  ///< EOF before the full frame arrived.
    Malformed,  ///< Bad magic or an out-of-bounds length.
    WriteError, ///< Spooling the body to disk failed.
    Error       ///< Transport read error.
};

constexpr uint32_t SYNC_FRAME_MAX_ID = 256;                       ///< Session-id length cap.
constexpr uint64_t SYNC_FRAME_MAX_BODY = 512ULL * 1024 * 1024;    ///< 512 MB body cap.

/// Frames and writes a whole session through the write callback. Returns false
/// on a transport write error.
bool writeSyncSessionFrame(const SyncWriteFn& write, const std::string& sessionId,
                           const uint8_t* body, size_t length);

/// Reads one framed session, streaming the body into `out` (already open for
/// writing). Fills sessionId and size on Ok. Body length is bounded by maxBody.
SyncFrameResult readSyncSessionFrame(const SyncReadFn& read, std::FILE* out,
                                     std::string& sessionId, uint64_t& size,
                                     uint64_t maxBody = SYNC_FRAME_MAX_BODY);

#endif // _HC_SYNC_FRAME_HPP
