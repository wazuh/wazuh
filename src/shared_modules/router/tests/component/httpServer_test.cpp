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
    /**
     * @brief Minimum RLIMIT_NOFILE needed by the test.
     */
    static constexpr rlim_t REQUIRED_NOFILE {FD_SETSIZE + 256};

    /**
     * @brief RLIMIT_NOFILE to restore on teardown.
     */
    rlimit m_oldLimit {};

    /**
     * @brief Descriptors opened to fill the ones below FD_SETSIZE.
     */
    std::vector<int> m_fds;

    /**
     * @brief Temporary directory holding the socket.
     */
    std::filesystem::path m_dir;

    /**
     * @brief Path of the UNIX socket served by the test.
     */
    std::string m_socket;

    /**
     * @brief Raises the descriptor limit and creates the temporary socket directory.
     */
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

    /**
     * @brief Closes the reserved descriptors, restores the limit and removes the temporary directory.
     */
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

    /**
     * @brief Fills every free descriptor below FD_SETSIZE so that any later one is above it.
     */
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
    ASSERT_NO_FATAL_FAILURE(exhaustLowDescriptors());

    httplib::Server server;
    server.set_address_family(AF_UNIX);
    server.Get("/ping", [](const httplib::Request&, httplib::Response& res) { res.set_content("pong", "text/plain"); });

    std::thread serverThread {[&]() { server.listen(m_socket, true); }};
    server.wait_until_ready();

    // Frees one descriptor below FD_SETSIZE for the client, so only the accepted socket is above it.
    close(m_fds.front());
    m_fds.erase(m_fds.begin());

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
