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

#include "syncFrame.hpp"

#include <algorithm>
#include <array>
#include <vector>

namespace
{
    constexpr size_t CHUNK = 64 * 1024;

    void putU32(std::vector<uint8_t>& out, uint32_t value)
    {
        for (int shift = 0; shift < 32; shift += 8)
        {
            out.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
        }
    }

    void putU64(std::vector<uint8_t>& out, uint64_t value)
    {
        for (int shift = 0; shift < 64; shift += 8)
        {
            out.push_back(static_cast<uint8_t>((value >> shift) & 0xff));
        }
    }

    uint32_t getU32(const uint8_t* buffer)
    {
        uint32_t value = 0;

        for (int index = 0; index < 4; index++)
        {
            value |= static_cast<uint32_t>(buffer[index]) << (index * 8);
        }

        return value;
    }

    uint64_t getU64(const uint8_t* buffer)
    {
        uint64_t value = 0;

        for (int index = 0; index < 8; index++)
        {
            value |= static_cast<uint64_t>(buffer[index]) << (index * 8);
        }

        return value;
    }

    bool writeAll(const SyncWriteFn& write, const void* data, size_t length)
    {
        const auto* cursor = static_cast<const uint8_t*>(data);
        size_t remaining = length;

        while (remaining > 0)
        {
            const long written = write(cursor, remaining);

            if (written <= 0)
            {
                return false;
            }

            cursor += written;
            remaining -= static_cast<size_t>(written);
        }

        return true;
    }

    /// Reads exactly n bytes. Returns Ok, Truncated (EOF early) or Error.
    SyncFrameResult readAll(const SyncReadFn& read, void* data, size_t length)
    {
        auto* cursor = static_cast<uint8_t*>(data);
        size_t remaining = length;

        while (remaining > 0)
        {
            const long got = read(cursor, remaining);

            if (got == 0)
            {
                return SyncFrameResult::Truncated;
            }

            if (got < 0)
            {
                return SyncFrameResult::Error;
            }

            cursor += got;
            remaining -= static_cast<size_t>(got);
        }

        return SyncFrameResult::Ok;
    }

    SyncFrameResult streamBodyToFile(const SyncReadFn& read, std::FILE* out, uint64_t bodyLength)
    {
        std::vector<uint8_t> chunk(CHUNK);
        uint64_t remaining = bodyLength;

        while (remaining > 0)
        {
            const size_t want = static_cast<size_t>(std::min<uint64_t>(remaining, CHUNK));
            const long got = read(chunk.data(), want);

            if (got == 0)
            {
                return SyncFrameResult::Truncated;
            }

            if (got < 0)
            {
                return SyncFrameResult::Error;
            }

            if (std::fwrite(chunk.data(), 1, static_cast<size_t>(got), out) != static_cast<size_t>(got))
            {
                return SyncFrameResult::WriteError;
            }

            remaining -= static_cast<uint64_t>(got);
        }

        return SyncFrameResult::Ok;
    }
} // namespace

bool writeSyncSessionFrame(const SyncWriteFn& write, const std::string& sessionId,
                           const uint8_t* body, size_t length)
{
    std::vector<uint8_t> header;
    header.reserve(SYNC_FRAME_MAGIC.size() + 4 + sessionId.size() + 8);
    header.insert(header.end(), SYNC_FRAME_MAGIC.begin(), SYNC_FRAME_MAGIC.end());
    putU32(header, static_cast<uint32_t>(sessionId.size()));
    header.insert(header.end(), sessionId.begin(), sessionId.end());
    putU64(header, static_cast<uint64_t>(length));

    if (!writeAll(write, header.data(), header.size()))
    {
        return false;
    }

    return length == 0 || writeAll(write, body, length);
}

SyncFrameResult readSyncSessionFrame(const SyncReadFn& read, std::FILE* out, std::string& sessionId,
                                     uint64_t& size, uint64_t maxBody)
{
    std::array<uint8_t, 4> magic {};

    if (const auto result = readAll(read, magic.data(), magic.size()); result != SyncFrameResult::Ok)
    {
        return result;
    }

    if (magic != SYNC_FRAME_MAGIC)
    {
        return SyncFrameResult::Malformed;
    }

    std::array<uint8_t, 4> idLenBytes {};

    if (const auto result = readAll(read, idLenBytes.data(), 4); result != SyncFrameResult::Ok)
    {
        return result;
    }

    const uint32_t idLen = getU32(idLenBytes.data());

    if (idLen == 0 || idLen > SESSION_ID_MAX_LENGTH)
    {
        return SyncFrameResult::Malformed;
    }

    std::string id(idLen, '\0');

    if (const auto result = readAll(read, id.data(), idLen); result != SyncFrameResult::Ok)
    {
        return result;
    }

    // The id ends up in the X-Session-Id header, so reject anything that could
    // break out of it before a single body byte is spooled.
    if (!isValidSessionId(id))
    {
        return SyncFrameResult::Malformed;
    }

    std::array<uint8_t, 8> bodyLenBytes {};

    if (const auto result = readAll(read, bodyLenBytes.data(), 8); result != SyncFrameResult::Ok)
    {
        return result;
    }

    const uint64_t bodyLen = getU64(bodyLenBytes.data());

    if (bodyLen > maxBody)
    {
        return SyncFrameResult::Malformed;
    }

    if (const auto result = streamBodyToFile(read, out, bodyLen); result != SyncFrameResult::Ok)
    {
        return result;
    }

    sessionId = std::move(id);
    size = bodyLen;
    return SyncFrameResult::Ok;
}

bool writeSyncSessionAck(const SyncWriteFn& write, bool accepted)
{
    const uint8_t status = accepted ? SYNC_FRAME_ACCEPTED : SYNC_FRAME_REFUSED;
    return writeAll(write, &status, sizeof(status));
}

bool readSyncSessionAck(const SyncReadFn& read)
{
    uint8_t status = SYNC_FRAME_REFUSED;

    if (readAll(read, &status, sizeof(status)) != SyncFrameResult::Ok)
    {
        return false; // No answer: assume the session was not taken.
    }

    return status == SYNC_FRAME_ACCEPTED;
}
