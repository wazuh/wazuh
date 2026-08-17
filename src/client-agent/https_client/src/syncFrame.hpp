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

#include "shared_modules/sync_protocol/include/sync_session_wire.hpp"

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
 * The wire layout, its bounds and the session-id charset live in
 * sync_session_wire.hpp, the one definition shared with the producer
 * (sync_protocol's SyncSocketTransport) so the two ends cannot drift.
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
    Malformed,  ///< Bad magic, an out-of-bounds length or an illegal session id.
    WriteError, ///< Spooling the body to disk failed.
    Error       ///< Transport read error.
};

/// Frames and writes a whole session through the write callback. Returns false
/// on a transport write error.
bool writeSyncSessionFrame(const SyncWriteFn& write, const std::string& sessionId,
                           const uint8_t* body, size_t length);

/// Reads one framed session, streaming the body into `out` (already open for
/// writing). Fills sessionId and size on Ok. Body length is bounded by maxBody.
SyncFrameResult readSyncSessionFrame(const SyncReadFn& read, std::FILE* out,
                                     std::string& sessionId, uint64_t& size,
                                     uint64_t maxBody = SYNC_FRAME_MAX_BODY);

/// Answers the producer with the one-byte outcome of its session.
bool writeSyncSessionAck(const SyncWriteFn& write, bool accepted);

/// Reads that byte back. Returns false when the session was refused, or when
/// no answer arrived at all (a refusal is the safe reading of silence).
bool readSyncSessionAck(const SyncReadFn& read);

#endif // _HC_SYNC_FRAME_HPP
