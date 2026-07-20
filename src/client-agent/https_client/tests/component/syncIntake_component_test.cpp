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

/*
 * End-to-end over a REAL Unix STREAM socket: a producer streams a whole
 * session through sendSyncSession(); the SyncIntake listener spools it and
 * hands (id, path, size) to the sink. Proves a multi-MB session crosses the
 * new intake with no 64 KB cap.
 */

#include "syncIntake.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <string>
#include <unistd.h>

namespace
{
    struct Received
    {
        std::mutex mutex;
        std::condition_variable cv;
        int count {0};
        std::string id;
        std::string path;
        uint64_t size {0};
    };

    std::string socketPath()
    {
        return "/tmp/hc_si_" + std::to_string(getpid()) + ".sock";
    }

    std::string readFile(const std::string& path)
    {
        std::ifstream file {path, std::ios::binary};
        return std::string {std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {}};
    }

    bool fileExists(const std::string& path)
    {
        return std::ifstream {path}.good();
    }

    bool sendBody(const std::string& sock, const std::string& id, const std::string& body)
    {
        return sendSyncSession(sock, id, reinterpret_cast<const uint8_t*>(body.data()), body.size());
    }

    // Waits until the intake has delivered `n` sessions to the sink.
    bool waitForCount(Received& received, int n)
    {
        std::unique_lock<std::mutex> lock(received.mutex);
        return received.cv.wait_for(lock, std::chrono::seconds {5}, [&] { return received.count >= n; });
    }
} // namespace

class SyncIntakeComponentTest : public ::testing::Test
{
    protected:
        SyncIntakeComponentTest()
            : m_intake(socketPath(), ::testing::TempDir(),
                       [this](const std::string & id, const std::string & path, uint64_t size)
        {
            std::lock_guard<std::mutex> lock(m_received.mutex);
            m_received.id = id;
            m_received.path = path;
            m_received.size = size;
            m_received.count++;
            m_received.cv.notify_all();
        })
        {
        }

        Received m_received;
        SyncIntake m_intake;
};

TEST_F(SyncIntakeComponentTest, StreamsAMultiMegabyteSessionThroughTheSocket)
{
    ASSERT_TRUE(m_intake.start());

    std::string body(3u * 1024 * 1024, '\0'); // 3 MB, far past the 64 KB DGRAM cap.

    for (size_t i = 0; i < body.size(); i++)
    {
        body[i] = static_cast<char>('a' + (i % 26));
    }

    ASSERT_TRUE(sendBody(socketPath(), "big-1", body));
    ASSERT_TRUE(waitForCount(m_received, 1));

    EXPECT_EQ("big-1", m_received.id);
    EXPECT_EQ(3u * 1024 * 1024, m_received.size);
    EXPECT_EQ(body, readFile(m_received.path)); // The whole session landed on disk.

    std::remove(m_received.path.c_str()); // The sink owns the spool file.
}

TEST_F(SyncIntakeComponentTest, HandlesSeveralSessionsInSequence)
{
    ASSERT_TRUE(m_intake.start());

    ASSERT_TRUE(sendBody(socketPath(), "s-1", "first session body"));
    ASSERT_TRUE(waitForCount(m_received, 1));
    EXPECT_EQ("s-1", m_received.id);
    std::remove(m_received.path.c_str());

    ASSERT_TRUE(sendBody(socketPath(), "s-2", std::string(100000, 'Q'))); // 100 KB
    ASSERT_TRUE(waitForCount(m_received, 2));
    EXPECT_EQ("s-2", m_received.id);
    EXPECT_EQ(100000u, m_received.size);
    std::remove(m_received.path.c_str());
}

TEST_F(SyncIntakeComponentTest, SpoolFileExistsWhenTheSinkIsCalled)
{
    ASSERT_TRUE(m_intake.start());
    ASSERT_TRUE(sendBody(socketPath(), "exists", "body-bytes"));
    ASSERT_TRUE(waitForCount(m_received, 1));
    EXPECT_TRUE(fileExists(m_received.path));
    std::remove(m_received.path.c_str());
}

TEST_F(SyncIntakeComponentTest, StartTwiceIsSafeAndStopIsIdempotent)
{
    ASSERT_TRUE(m_intake.start());
    EXPECT_TRUE(m_intake.start()); // Already running.
    m_intake.stop();
    m_intake.stop(); // Idempotent.
}

TEST(SyncIntakeSenderTest, SendToAMissingSocketFails)
{
    const std::string body = "x";
    EXPECT_FALSE(sendSyncSession("/tmp/hc_si_nonexistent.sock", "s",
                                 reinterpret_cast<const uint8_t*>(body.data()), body.size()));
}
