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

// Pure framing tests: no socket. A writer callback appends to an in-memory
// pipe; a reader callback drains it. The body is streamed into a temp file.

#include "syncFrame.hpp"

#include "shared_modules/sync_protocol/include/sync_session_wire.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace
{
    /// In-memory byte pipe: write appends, read drains from a cursor.
    struct MemPipe
    {
        std::vector<uint8_t> data;
        size_t cursor {0};

        SyncWriteFn writer()
        {
            return [this](const void* buffer, size_t n) -> long
            {
                const auto* bytes = static_cast<const uint8_t*>(buffer);
                data.insert(data.end(), bytes, bytes + n);
                return static_cast<long>(n);
            };
        }

        SyncReadFn reader()
        {
            return [this](void* buffer, size_t n) -> long
            {
                const size_t avail = data.size() - cursor;
                const size_t take = std::min(n, avail);

                if (take == 0)
                {
                    return 0; // EOF
                }

                std::memcpy(buffer, data.data() + cursor, take);
                cursor += take;
                return static_cast<long>(take);
            };
        }
    };

    std::string roundTrip(const std::string& id, const std::string& body, SyncFrameResult& result,
                          uint64_t& sizeOut, std::string& idOut)
    {
        MemPipe pipe;
        EXPECT_TRUE(writeSyncSessionFrame(pipe.writer(), id,
                                          reinterpret_cast<const uint8_t*>(body.data()), body.size()));
        const std::string path = ::testing::TempDir() + "hc_syncframe.tmp";
        std::FILE* out = std::fopen(path.c_str(), "wb");
        result = readSyncSessionFrame(pipe.reader(), out, idOut, sizeOut);
        std::fclose(out);
        std::ifstream in {path, std::ios::binary};
        std::string got {std::istreambuf_iterator<char> {in}, std::istreambuf_iterator<char> {}};
        std::remove(path.c_str());
        return got;
    }
} // namespace

TEST(SyncFrameTest, RoundTripsASmallSession)
{
    SyncFrameResult result {};
    uint64_t size {0};
    std::string id;
    const std::string body = "FULLSESSION:syscollector:some-body-bytes";
    const std::string got = roundTrip("sess-1", body, result, size, id);

    EXPECT_EQ(SyncFrameResult::Ok, result);
    EXPECT_EQ("sess-1", id);
    EXPECT_EQ(body.size(), size);
    EXPECT_EQ(body, got);
}

TEST(SyncFrameTest, RoundTripsAMultiMegabyteSessionPastThe64kCap)
{
    SyncFrameResult result {};
    uint64_t size {0};
    std::string id;
    // 3 MB — far beyond the legacy 64 KB DGRAM message cap.
    std::string body(3u * 1024 * 1024, '\0');

    for (size_t i = 0; i < body.size(); i++)
    {
        body[i] = static_cast<char>('A' + (i % 26));
    }

    const std::string got = roundTrip("big-session", body, result, size, id);

    EXPECT_EQ(SyncFrameResult::Ok, result);
    EXPECT_EQ(3u * 1024 * 1024, size);
    EXPECT_EQ(body, got);
}

TEST(SyncFrameTest, EmptyBodyIsValid)
{
    SyncFrameResult result {};
    uint64_t size {0};
    std::string id;
    const std::string got = roundTrip("empty", "", result, size, id);
    EXPECT_EQ(SyncFrameResult::Ok, result);
    EXPECT_EQ(0u, size);
    EXPECT_TRUE(got.empty());
    EXPECT_EQ("empty", id);
}

TEST(SyncFrameTest, TruncatedFrameIsDetected)
{
    MemPipe pipe;
    const std::string body = "0123456789";
    writeSyncSessionFrame(pipe.writer(), "sess", reinterpret_cast<const uint8_t*>(body.data()),
                          body.size());
    pipe.data.resize(pipe.data.size() - 4); // Chop the tail of the body.

    std::string id;
    uint64_t size {0};
    std::FILE* out = std::tmpfile();
    EXPECT_EQ(SyncFrameResult::Truncated, readSyncSessionFrame(pipe.reader(), out, id, size));
    std::fclose(out);
}

TEST(SyncFrameTest, BadMagicIsMalformed)
{
    MemPipe pipe;
    const std::string junk = "NOTAFRAMExxxxxxxxxxxxxxxx";
    pipe.data.assign(junk.begin(), junk.end());
    std::string id;
    uint64_t size {0};
    std::FILE* out = std::tmpfile();
    EXPECT_EQ(SyncFrameResult::Malformed, readSyncSessionFrame(pipe.reader(), out, id, size));
    std::fclose(out);
}

TEST(SyncFrameTest, OversizedBodyLengthIsRejected)
{
    MemPipe pipe;
    const std::string body = "x";
    writeSyncSessionFrame(pipe.writer(), "s", reinterpret_cast<const uint8_t*>(body.data()),
                          body.size());
    std::string id;
    uint64_t size {0};
    std::FILE* out = std::tmpfile();
    // Cap the body at 0 bytes: the 1-byte body exceeds it -> Malformed.
    EXPECT_EQ(SyncFrameResult::Malformed, readSyncSessionFrame(pipe.reader(), out, id, size, 0));
    std::fclose(out);
}

TEST(SyncFrameTest, WriteErrorIsReported)
{
    const auto failingWrite = [](const void*, size_t) -> long { return -1; };
    const std::string body = "abc";
    EXPECT_FALSE(writeSyncSessionFrame(failingWrite, "s",
                                       reinterpret_cast<const uint8_t*>(body.data()), body.size()));
}

TEST(SyncFrameTest, ZeroLengthIdIsMalformed)
{
    // Hand-craft a frame with id_len = 0.
    MemPipe pipe;
    pipe.data = {'W', 'Z', 'S', 'Y', 0, 0, 0, 0}; // magic + id_len(0)
    std::string id;
    uint64_t size {0};
    std::FILE* out = std::tmpfile();
    EXPECT_EQ(SyncFrameResult::Malformed, readSyncSessionFrame(pipe.reader(), out, id, size));
    std::fclose(out);
}

TEST(SyncFrameTest, AnIdWithControlBytesIsMalformed)
{
    // A producer is free to put anything in the id field; the reader must
    // reject it before a body byte is spooled, because the id later becomes
    // the X-Session-Id header.
    SyncFrameResult result {};
    uint64_t size {0};
    std::string idOut;

    roundTrip("sess\r\nX-Injected: 1", "body", result, size, idOut);
    EXPECT_EQ(SyncFrameResult::Malformed, result);
    EXPECT_TRUE(idOut.empty());

    roundTrip("sess with spaces", "body", result, size, idOut);
    EXPECT_EQ(SyncFrameResult::Malformed, result);

    roundTrip(std::string(SESSION_ID_MAX_LENGTH + 1, 'a'), "body", result, size, idOut);
    EXPECT_EQ(SyncFrameResult::Malformed, result);
}

TEST(SyncFrameTest, TheIdShapesProducersUseRoundTrip)
{
    SyncFrameResult result {};
    uint64_t size {0};
    std::string idOut;

    EXPECT_EQ("body", roundTrip("3f2504e0-4f89-11d3-9a0c-0305e82c3301", "body", result, size, idOut));
    EXPECT_EQ(SyncFrameResult::Ok, result);
    EXPECT_EQ("3f2504e0-4f89-11d3-9a0c-0305e82c3301", idOut);

    EXPECT_EQ("body", roundTrip("fim.full_sync-42", "body", result, size, idOut));
    EXPECT_EQ(SyncFrameResult::Ok, result);
    EXPECT_EQ("fim.full_sync-42", idOut);
}

TEST(SyncFrameTest, TheStatusByteRoundTripsBothWays)
{
    MemPipe accepted;
    EXPECT_TRUE(writeSyncSessionAck(accepted.writer(), true));
    EXPECT_TRUE(readSyncSessionAck(accepted.reader()));

    MemPipe refused;
    EXPECT_TRUE(writeSyncSessionAck(refused.writer(), false));
    EXPECT_FALSE(readSyncSessionAck(refused.reader()));
}

TEST(SyncFrameTest, AMissingStatusByteReadsAsARefusal)
{
    // The producer still owns a session it never got an answer for, so silence
    // and an unreadable socket both have to mean "not taken".
    MemPipe empty;
    EXPECT_FALSE(readSyncSessionAck(empty.reader())); // EOF.

    const auto failingRead = [](void*, size_t) -> long { return -1; };
    EXPECT_FALSE(readSyncSessionAck(failingRead));
}
