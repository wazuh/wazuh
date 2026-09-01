/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _WIN32

#include "gtest/gtest.h"

#include "sync_session_wire.hpp"
#include "sync_socket_transport.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace
{
    bool readExact(int fd, void* data, size_t length)
    {
        auto* cursor = static_cast<uint8_t*>(data);
        size_t remaining = length;

        while (remaining > 0)
        {
            const auto got = recv(fd, cursor, remaining, 0);

            if (got < 0 && errno == EINTR)
            {
                continue;
            }

            if (got <= 0)
            {
                return false;
            }

            cursor += got;
            remaining -= static_cast<size_t>(got);
        }

        return true;
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

    /// A stand-in for the HTTPS client's queue-sync intake: accepts one
    /// connection, reads one WZSY frame and answers (or misbehaves) per the
    /// configured behavior.
    class FakeIntake
    {
        public:
            enum class Behavior
            {
                Accept,          ///< Read the frame, answer SYNC_FRAME_ACCEPTED.
                Refuse,          ///< Read the frame, answer SYNC_FRAME_REFUSED.
                CloseWithoutAck, ///< Read the frame, close with no status byte.
                Stall            ///< Read nothing, keep the connection open.
            };

            FakeIntake(std::string path, Behavior behavior)
                : m_path(std::move(path))
                , m_behavior(behavior)
            {
                listenAndServe(); // ASSERT_* needs a void function, not a constructor.
            }

            ~FakeIntake()
            {
                waitDone();

                if (m_listenFd >= 0)
                {
                    close(m_listenFd);
                }

                unlink(m_path.c_str());
            }

            /// Joins the serving thread; call before asserting on the capture.
            void waitDone()
            {
                if (m_thread.joinable())
                {
                    m_thread.join();
                }
            }

            const std::string& capturedSessionId() const
            {
                return m_sessionId;
            }

            const std::vector<uint8_t>& capturedBody() const
            {
                return m_body;
            }

            bool magicMatched() const
            {
                return m_magicOk;
            }

        private:
            void listenAndServe()
            {
                m_listenFd = socket(AF_UNIX, SOCK_STREAM, 0);
                ASSERT_GE(m_listenFd, 0);

                sockaddr_un addr {};
                addr.sun_family = AF_UNIX;
                std::strncpy(addr.sun_path, m_path.c_str(), sizeof(addr.sun_path) - 1);
                unlink(m_path.c_str());
                ASSERT_EQ(bind(m_listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
                ASSERT_EQ(listen(m_listenFd, 1), 0);

                m_thread = std::thread([this]
                {
                    serve();
                });
            }

            void serve()
            {
                const int fd = accept(m_listenFd, nullptr, nullptr);

                if (fd < 0)
                {
                    return;
                }

                if (m_behavior == Behavior::Stall)
                {
                    // Outlive the producer's I/O timeout without ever reading.
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    close(fd);
                    return;
                }

                std::array<uint8_t, 4> magic {};

                if (!readExact(fd, magic.data(), magic.size()))
                {
                    close(fd);
                    return;
                }

                m_magicOk = (magic == SYNC_FRAME_MAGIC);

                std::array<uint8_t, 4> idLenBytes {};

                if (!readExact(fd, idLenBytes.data(), idLenBytes.size()))
                {
                    close(fd);
                    return;
                }

                const uint32_t idLen = getU32(idLenBytes.data());
                std::string id(idLen, '\0');

                if (idLen > 0 && !readExact(fd, id.data(), idLen))
                {
                    close(fd);
                    return;
                }

                std::array<uint8_t, 8> bodyLenBytes {};

                if (!readExact(fd, bodyLenBytes.data(), bodyLenBytes.size()))
                {
                    close(fd);
                    return;
                }

                const uint64_t bodyLen = getU64(bodyLenBytes.data());
                std::vector<uint8_t> body(bodyLen);

                if (bodyLen > 0 && !readExact(fd, body.data(), body.size()))
                {
                    close(fd);
                    return;
                }

                m_sessionId = std::move(id);
                m_body = std::move(body);

                if (m_behavior != Behavior::CloseWithoutAck)
                {
                    const uint8_t status = (m_behavior == Behavior::Accept)
                                           ? SYNC_FRAME_ACCEPTED
                                           : SYNC_FRAME_REFUSED;
                    send(fd, &status, sizeof(status), 0);
                }

                close(fd);
            }

            std::string m_path;
            Behavior m_behavior;
            int m_listenFd {-1};
            std::thread m_thread;
            std::string m_sessionId;
            std::vector<uint8_t> m_body;
            bool m_magicOk {false};
    };

    class SyncSocketTransportTest : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                char pathTemplate[] = "/tmp/wzsyncXXXXXX";
                ASSERT_NE(mkdtemp(pathTemplate), nullptr);
                m_dir = pathTemplate;
                m_socketPath = m_dir + "/queue-sync";
            }

            void TearDown() override
            {
                unlink(m_socketPath.c_str());
                rmdir(m_dir.c_str());
            }

            LoggerFunc captureLogger()
            {
                return [this](modules_log_level_t, const std::string & msg)
                {
                    std::lock_guard<std::mutex> lock(m_logMutex);
                    m_logs.push_back(msg);
                };
            }

            bool loggedContains(const std::string& needle)
            {
                std::lock_guard<std::mutex> lock(m_logMutex);

                for (const auto& line : m_logs)
                {
                    if (line.find(needle) != std::string::npos)
                    {
                        return true;
                    }
                }

                return false;
            }

            std::string m_dir;
            std::string m_socketPath;
            std::mutex m_logMutex;
            std::vector<std::string> m_logs;
    };
} // namespace

TEST_F(SyncSocketTransportTest, FrameSessionIdIsModuleDashSession)
{
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());
    EXPECT_EQ(transport.frameSessionId(42), "mod-42");
}

TEST_F(SyncSocketTransportTest, DeliversWholeFrameAndReportsAcceptance)
{
    FakeIntake intake(m_socketPath, FakeIntake::Behavior::Accept);
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());

    const std::vector<uint8_t> body {0x01, 0x02, 0x03, 0xFF, 0x00, 0x7F};
    EXPECT_TRUE(transport.sendSession(123, body));

    intake.waitDone();
    EXPECT_TRUE(intake.magicMatched());
    EXPECT_EQ(intake.capturedSessionId(), "mod-123");
    EXPECT_EQ(intake.capturedBody(), body);
}

TEST_F(SyncSocketTransportTest, EmptyMessageStillFramesAndAcks)
{
    FakeIntake intake(m_socketPath, FakeIntake::Behavior::Accept);
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());

    EXPECT_TRUE(transport.sendSession(7, {}));

    intake.waitDone();
    EXPECT_EQ(intake.capturedSessionId(), "mod-7");
    EXPECT_TRUE(intake.capturedBody().empty());
}

TEST_F(SyncSocketTransportTest, RefusedSessionReportsFailure)
{
    FakeIntake intake(m_socketPath, FakeIntake::Behavior::Refuse);
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());

    EXPECT_FALSE(transport.sendSession(123, {0x01}));
}

TEST_F(SyncSocketTransportTest, SilenceReadsAsRefusal)
{
    FakeIntake intake(m_socketPath, FakeIntake::Behavior::CloseWithoutAck);
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());

    EXPECT_FALSE(transport.sendSession(123, {0x01}));
}

TEST_F(SyncSocketTransportTest, UnreachableIntakeFailsBothCalls)
{
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());

    EXPECT_FALSE(transport.checkStatus());
    EXPECT_FALSE(transport.sendSession(123, {0x01}));
}

TEST_F(SyncSocketTransportTest, ReachableIntakeReportsAvailable)
{
    FakeIntake intake(m_socketPath, FakeIntake::Behavior::Stall);
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger());

    EXPECT_TRUE(transport.checkStatus());
}

TEST_F(SyncSocketTransportTest, StalledIntakeTimesOutInsteadOfHanging)
{
    FakeIntake intake(m_socketPath, FakeIntake::Behavior::Stall);
    SyncSocketTransport transport(m_socketPath, "mod", captureLogger(),
                                  std::chrono::milliseconds {100});

    const auto before = std::chrono::steady_clock::now();
    EXPECT_FALSE(transport.sendSession(123, {0x01}));
    const auto elapsed = std::chrono::steady_clock::now() - before;

    // Bounded by the I/O timeout, not by the intake deciding to answer.
    EXPECT_LT(elapsed, std::chrono::milliseconds {900});
}

TEST_F(SyncSocketTransportTest, OutOfContractModuleNameFailsFast)
{
    SyncSocketTransport transport(m_socketPath, "bad\nname", captureLogger());

    EXPECT_FALSE(transport.sendSession(1, {0x01}));
    EXPECT_TRUE(loggedContains("violates the wire contract"));
}

#endif // _WIN32
