/*
 * Wazuh keystore server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keystore_server.h"

#include <json.hpp>

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

/*
 * The pipe protocol on `queue/sockets/keystore` is a live contract with the Python framework's
 * KeystoreClient (framework/wazuh/core/indexer/credential_manager.py fetches the indexer
 * credentials through it), and it had ZERO tests while it lived inside inventory_sync. These pin
 * it byte-for-byte as it moves into its own module -- including the deliberate oddity that a GET
 * of an empty/absent value answers the literal "wazuh-manager".
 */

namespace
{
    std::string uniqueSocketPath()
    {
        static std::atomic<int> counter {0};
        return "/tmp/kss_" + std::to_string(::getpid()) + "_" + std::to_string(counter.fetch_add(1)) + ".sock";
    }

    /// A key unique per test run, so a keystore RocksDB left over from a previous run cannot leak
    /// state into the "missing key" assertions.
    std::string uniqueKey(const char* tag)
    {
        return std::string {tag} + "-" + std::to_string(::getpid()) + "-" +
               std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    }

    /**
     * @brief Minimal SizeHeaderProtocol client: 4-byte little-endian length prefix + body, one
     *        request per connection -- the exact wire shape the Python WazuhSocket client uses.
     */
    nlohmann::json query(const std::string& socketPath, const std::string& request)
    {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            ADD_FAILURE() << "socket() failed";
            return {};
        }

        sockaddr_un address {};
        address.sun_family = AF_UNIX;
        std::strncpy(address.sun_path, socketPath.c_str(), sizeof(address.sun_path) - 1);

        // The server binds asynchronously fast, but not instantly: retry the connect briefly.
        int connected = -1;
        for (int attempt = 0; attempt < 100 && connected != 0; ++attempt)
        {
            connected = ::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
            if (connected != 0)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds {10});
            }
        }
        if (connected != 0)
        {
            ::close(fd);
            ADD_FAILURE() << "could not connect to " << socketPath;
            return {};
        }

        const auto size = static_cast<std::uint32_t>(request.size());
        std::string frame(sizeof(size), '\0');
        std::memcpy(frame.data(), &size, sizeof(size));
        frame += request;
        if (::write(fd, frame.data(), frame.size()) != static_cast<ssize_t>(frame.size()))
        {
            ::close(fd);
            ADD_FAILURE() << "short write";
            return {};
        }

        std::uint32_t responseSize {0};
        if (::read(fd, &responseSize, sizeof(responseSize)) != sizeof(responseSize) || responseSize == 0 ||
            responseSize > 1024U * 1024U)
        {
            ::close(fd);
            ADD_FAILURE() << "bad response header";
            return {};
        }
        std::string body(responseSize, '\0');
        std::size_t got {0};
        while (got < responseSize)
        {
            const auto n = ::read(fd, body.data() + got, responseSize - got);
            if (n <= 0)
            {
                break;
            }
            got += static_cast<std::size_t>(n);
        }
        ::close(fd);

        if (got != responseSize)
        {
            ADD_FAILURE() << "short read";
            return {};
        }
        return nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    }
} // namespace

class KeystoreServerProtocolTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_path = uniqueSocketPath();
        ASSERT_EQ(0, keystore_server_start(nullptr, m_path.c_str()));
    }

    void TearDown() override
    {
        keystore_server_stop();
    }

    std::string m_path;
};

TEST_F(KeystoreServerProtocolTest, PutThenGetRoundTrips)
{
    const auto key = uniqueKey("roundtrip");

    const auto put = query(m_path, "PUT|default|" + key + "|s3cret-value");
    EXPECT_EQ("ok", put.value("status", ""));
    EXPECT_EQ("put", put.value("operation", ""));
    EXPECT_EQ("default", put.value("columnFamily", ""));
    EXPECT_EQ(key, put.value("key", ""));

    const auto get = query(m_path, "GET|default|" + key);
    EXPECT_EQ("ok", get.value("status", ""));
    EXPECT_EQ("get", get.value("operation", ""));
    EXPECT_EQ("s3cret-value", get.value("value", ""));
}

TEST_F(KeystoreServerProtocolTest, AMissingKeyAnswersTheWazuhManagerDefault)
{
    // The framework's credential_manager may depend on this literal; it is preserved, not fixed.
    const auto get = query(m_path, "GET|default|" + uniqueKey("missing"));
    EXPECT_EQ("ok", get.value("status", ""));
    EXPECT_EQ("wazuh-manager", get.value("value", ""));
}

TEST_F(KeystoreServerProtocolTest, DeleteIsAPutOfEmptyAndFallsBackToTheDefault)
{
    const auto key = uniqueKey("delete");

    ASSERT_EQ("ok", query(m_path, "PUT|default|" + key + "|to-be-deleted").value("status", ""));

    const auto del = query(m_path, "DELETE|default|" + key);
    EXPECT_EQ("ok", del.value("status", ""));
    EXPECT_EQ("delete", del.value("operation", ""));

    // Deleted == empty == the default literal, exactly like the legacy behavior.
    EXPECT_EQ("wazuh-manager", query(m_path, "GET|default|" + key).value("value", ""));
}

TEST_F(KeystoreServerProtocolTest, AnUnknownOperationIsAnError)
{
    const auto response = query(m_path, "LIST|default|whatever");
    EXPECT_EQ("error", response.value("status", ""));
    EXPECT_EQ("Unknown operation", response.value("message", ""));
}

TEST_F(KeystoreServerProtocolTest, AMalformedQueryIsAnErrorNotACrash)
{
    const auto response = query(m_path, "garbage-without-pipes");
    EXPECT_EQ("error", response.value("status", ""));
    EXPECT_EQ("Invalid query format", response.value("message", ""));
}

TEST_F(KeystoreServerProtocolTest, StopIsIdempotentAndTheModuleRestarts)
{
    keystore_server_stop();
    keystore_server_stop(); // idempotent

    const auto path = uniqueSocketPath();
    ASSERT_EQ(0, keystore_server_start(nullptr, path.c_str()));
    EXPECT_EQ("ok", query(path, "GET|default|" + uniqueKey("restart")).value("status", ""));
    keystore_server_stop();
}

TEST_F(KeystoreServerProtocolTest, ADoubleStartIsToleratedAndKeepsServing)
{
    EXPECT_EQ(0, keystore_server_start(nullptr, m_path.c_str())); // warns, keeps the first server
    EXPECT_EQ("ok", query(m_path, "GET|default|" + uniqueKey("double")).value("status", ""));
}
