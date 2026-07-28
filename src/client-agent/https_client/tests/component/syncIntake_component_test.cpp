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

#include "syncFrame.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>

#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
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

    /// Connects and writes `bytes` without ever finishing the frame, leaving the
    /// connection open. Returns the still-connected fd (-1 on failure).
    int connectAndStall(const std::string& sock, const std::string& bytes)
    {
        const int fd = socket(AF_UNIX, SOCK_STREAM, 0);

        if (fd < 0)
        {
            return -1;
        }

        sockaddr_un addr {};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, sock.c_str(), sizeof(addr.sun_path) - 1);

        if (connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
        {
            close(fd);
            return -1;
        }

        if (!bytes.empty() && write(fd, bytes.data(), bytes.size()) < 0)
        {
            close(fd); // LCOV_EXCL_LINE
            return -1; // LCOV_EXCL_LINE
        }

        return fd;
    }

    /// Caps how much any file this process writes may hold, so a spool that is
    /// small enough to sit in the stdio buffer only fails when it is flushed at
    /// close. Restores the previous limit (and SIGXFSZ disposition) on scope
    /// exit, since both are process-wide.
    class FileSizeCap final
    {
        public:
            explicit FileSizeCap(rlim_t bytes)
            {
                getrlimit(RLIMIT_FSIZE, &m_previous);
                m_previousHandler = signal(SIGXFSZ, SIG_IGN); // Else the write kills the process.
                rlimit capped {bytes, m_previous.rlim_max};
                m_applied = setrlimit(RLIMIT_FSIZE, &capped) == 0;
            }

            ~FileSizeCap()
            {
                setrlimit(RLIMIT_FSIZE, &m_previous);
                signal(SIGXFSZ, m_previousHandler);
            }

            FileSizeCap(const FileSizeCap&) = delete;
            FileSizeCap& operator=(const FileSizeCap&) = delete;

            bool applied() const
            {
                return m_applied;
            }

        private:
            rlimit m_previous {};
            void (*m_previousHandler)(int)
            {
                SIG_DFL
            };
            bool m_applied {false};
    };
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
            return m_accept.load(); // Flipped by the back-pressure test.
        })
        {
        }

        std::atomic<bool> m_accept {true};

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

TEST_F(SyncIntakeComponentTest, StopReturnsWhileAProducerIsStalledMidFrame)
{
    // A producer that sends half a frame and then goes quiet must not pin the
    // acceptor thread: stop() reaches the blocked read through the stop pipe.
    ASSERT_TRUE(m_intake.start());

    // "WZSY" + idLen=2, but only one of the two id bytes: the reader is now
    // blocked waiting for the rest, with the connection still open.
    const std::string partial {"WZSY\x02\x00\x00\x00i", 9};
    const int producer = connectAndStall(socketPath(), partial);
    ASSERT_GE(producer, 0);
    // Best effort: there is no signal for "the acceptor is now inside the
    // read". If this were ever too short the test would pass without having
    // exercised the fix, so it is deliberately longer than the accept path.
    std::this_thread::sleep_for(std::chrono::milliseconds {500});

    std::atomic<bool> returned {false};
    std::thread stopper {[this, &returned] { m_intake.stop(); returned = true; }};

    // Generous: this is a hang detector, not a timing assertion, and a real
    // hang is unbounded. Valgrind cannot make a correct stop() miss this.
    for (int attempt = 0; attempt < 150 && !returned; attempt++)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {100});
    }

    EXPECT_TRUE(returned) << "stop() blocked on a stalled producer";
    stopper.join(); // Only returns if stop() did; a regression wedges here.
    close(producer);
    EXPECT_EQ(0, m_received.count); // The half-frame was discarded, not promoted.
}

TEST_F(SyncIntakeComponentTest, ADeadProducerDoesNotBlockTheNextSession)
{
    // Head-of-line: the acceptor is single-threaded, so a peer that connects
    // and then dies without sending must not wedge the sessions behind it. A
    // peer that stays connected and silent is bounded by the idle timeout
    // instead, which is too long to assert on here.
    ASSERT_TRUE(m_intake.start());

    const int idle = connectAndStall(socketPath(), {}); // Connected, zero bytes.
    ASSERT_GE(idle, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds {200});

    close(idle); // The peer dies; the intake sees EOF and moves on.
    ASSERT_TRUE(sendBody(socketPath(), "after-stall", "body-bytes"));
    ASSERT_TRUE(waitForCount(m_received, 1));
    EXPECT_EQ("after-stall", m_received.id);
    std::remove(m_received.path.c_str());
}

TEST_F(SyncIntakeComponentTest, ARefusedSessionIsReportedBackToTheProducer)
{
    // The producer is another process: the send() returning true is all it has
    // to go on. A session the sink could not take must therefore come back as
    // a failed send, not a successful one.
    ASSERT_TRUE(m_intake.start());

    m_accept = false;
    EXPECT_FALSE(sendBody(socketPath(), "refused-1", "body-bytes"));
    ASSERT_TRUE(waitForCount(m_received, 1)); // It did reach the sink, and was declined.

    m_accept = true;
    EXPECT_TRUE(sendBody(socketPath(), "accepted-1", "body-bytes"));
    ASSERT_TRUE(waitForCount(m_received, 2));
    std::remove(m_received.path.c_str());
}

TEST_F(SyncIntakeComponentTest, AMalformedFrameIsReportedBackToTheProducer)
{
    // Nothing reached the sink at all, so the answer must still be a refusal.
    ASSERT_TRUE(m_intake.start());

    const int producer = connectAndStall(socketPath(), "NOTWZSY-garbage");
    ASSERT_GE(producer, 0);

    timeval timeout {};
    timeout.tv_sec = 5; // Never block the run if the answer stops coming.
    setsockopt(producer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    uint8_t status = SYNC_FRAME_ACCEPTED;
    EXPECT_EQ(1, read(producer, &status, 1));
    EXPECT_EQ(SYNC_FRAME_REFUSED, status);
    close(producer);
    EXPECT_EQ(0, m_received.count);
}

TEST_F(SyncIntakeComponentTest, ASpoolThatFailsToFlushAtCloseIsNotPromoted)
{
    // 2 KB fits the stdio buffer, so every fwrite() reports success and the
    // write only fails when close() flushes it past the 1 KB cap - the disk-
    // full shape. The half-written spool must be dropped, not handed on as a
    // complete session.
    ASSERT_TRUE(m_intake.start());

    const FileSizeCap cap {1024};
    ASSERT_TRUE(cap.applied());

    // The bytes crossed the socket fine, but the spool never reached disk, so
    // the producer is told the session was not taken. The send only returns
    // once that answer arrives, which is also when the sink has been decided -
    // no sleep needed, and nothing to drift under valgrind.
    EXPECT_FALSE(sendBody(socketPath(), "unflushable", std::string(2048, 'Z')));

    std::lock_guard<std::mutex> lock(m_received.mutex);
    EXPECT_EQ(0, m_received.count) << "a spool that never reached disk was promoted";
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

TEST(SyncIntakePathTest, APathTooLongForSunPathIsRefusedOnBothSides)
{
    // sun_path is 108 bytes and cannot signal truncation: binding the short
    // form while unlink() targets the long one would strand a stale socket and
    // break the next start with EADDRINUSE. Both sides refuse instead.
    const std::string tooLong = "/tmp/" + std::string(120, 'p') + ".sock";
    SyncIntake intake {tooLong, ::testing::TempDir(),
                       [](const std::string&, const std::string&, uint64_t)
    {
        return true;
    }};
    EXPECT_FALSE(intake.start());

    const std::string body = "x";
    EXPECT_FALSE(sendSyncSession(tooLong, "s", reinterpret_cast<const uint8_t*>(body.data()),
                                 body.size()));
    EXPECT_FALSE(sendSyncSession("", "s", reinterpret_cast<const uint8_t*>(body.data()),
                                 body.size()));
}
