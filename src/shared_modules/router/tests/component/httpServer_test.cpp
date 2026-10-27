/*
 * Wazuh router - HTTP server tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "external/cpp-httplib/httplib.h"
#include <algorithm>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <sys/resource.h>
#include <thread>
#include <unistd.h>
#include <vector>

/**
 * @brief Runs component tests for the HTTP server over a UNIX socket with descriptors above FD_SETSIZE.
 */
class HttpServerHighFdTest : public ::testing::Test
{
protected:
    static constexpr rlim_t REQUIRED_NOFILE {FD_SETSIZE + 256};

    rlimit m_oldLimit {};
    std::vector<int> m_fds;
    std::filesystem::path m_dir;
    std::string m_socket;

    void SetUp() override
    {
        ASSERT_EQ(getrlimit(RLIMIT_NOFILE, &m_oldLimit), 0);
        if (m_oldLimit.rlim_max < REQUIRED_NOFILE)
        {
            GTEST_SKIP() << "RLIMIT_NOFILE hard limit is lower than " << REQUIRED_NOFILE;
        }

        auto limit {m_oldLimit};
        limit.rlim_cur = std::max(limit.rlim_cur, REQUIRED_NOFILE);
        ASSERT_EQ(setrlimit(RLIMIT_NOFILE, &limit), 0);

        char dirTemplate[] = "/tmp/router_http_XXXXXX";
        ASSERT_NE(mkdtemp(dirTemplate), nullptr);
        m_dir = dirTemplate;
        m_socket = (m_dir / "test.sock").string();
    }

    void TearDown() override
    {
        for (const auto fd : m_fds)
        {
            close(fd);
        }
        setrlimit(RLIMIT_NOFILE, &m_oldLimit);
        std::error_code ec;
        std::filesystem::remove_all(m_dir, ec);
    }

    // Fills every free descriptor below FD_SETSIZE so that any later one is above it.
    void exhaustLowDescriptors()
    {
        int fd {};
        do
        {
            fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
            ASSERT_GE(fd, 0);
            m_fds.push_back(fd);
        } while (fd < FD_SETSIZE);
    }
};

TEST_F(HttpServerHighFdTest, ServesRequestsOnDescriptorsAboveFdSetSize)
{
    exhaustLowDescriptors();

    httplib::Server server;
    server.set_address_family(AF_UNIX);
    server.Get("/ping", [](const httplib::Request&, httplib::Response& res) { res.set_content("pong", "text/plain"); });

    std::thread serverThread {[&]() { server.listen(m_socket, true); }};
    server.wait_until_ready();

    // Each client gets its own connection, so the server accepts every one on a high descriptor.
    for (auto i = 0; i < 3; ++i)
    {
        httplib::Client client {m_socket};
        client.set_address_family(AF_UNIX);
        client.set_read_timeout(2, 0);

        const auto res {client.Get("/ping")};
        if (!res)
        {
            ADD_FAILURE() << "Request " << i << " failed: " << httplib::to_string(res.error());
            break;
        }
        EXPECT_EQ(res->status, 200);
        EXPECT_EQ(res->body, "pong");
    }

    server.stop();
    serverThread.join();
}
