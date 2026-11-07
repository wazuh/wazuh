/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/runtime.hpp"

namespace
{
    /// Runs `nm <options> -C` on the library; false (with the reason in `output`) if nm failed.
    bool nmOfLibrary(const std::string& options, std::string& output)
    {
        const std::string command = "nm " + options + " -C '" + INDEXER_CLIENT_SO_PATH + "' 2>&1";
        FILE* pipe = popen(command.c_str(), "r");
        if (pipe == nullptr)
        {
            output = "cannot run: " + command;
            return false;
        }
        char buffer[4096];
        std::size_t read = 0;
        while ((read = fread(buffer, 1, sizeof(buffer), pipe)) > 0)
        {
            output.append(buffer, read);
        }
        const int status = pclose(pipe);
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
} // namespace

// RNF-1: the library exports its API and nothing from its private dependencies: asio (ASIO_DISABLE_VISIBILITY +
// -fvisibility=hidden), and libcurl, simdjson and OpenSSL once E2 links them (--exclude-libs,ALL).
TEST(VisibilityTest, ExportsApiAndNoAsio)
{
    std::string output;
    ASSERT_TRUE(nmOfLibrary("-D --defined-only", output)) << "nm failed: " << output;
    ASSERT_FALSE(output.empty()) << "nm produced no output for " << INDEXER_CLIENT_SO_PATH;

    // Substrings of a demangled `nm` line that a private dependency would leave behind.
    const char* const denied[] = {"asio::", "curl_", "simdjson::", "SSL_", "CRYPTO_", "OPENSSL_"};

    std::size_t startSymbols = 0;
    std::size_t setLogFunctionSymbols = 0;
    std::size_t deniedLines = 0;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line))
    {
        if (line.find("indexer_client::RuntimeOwner::start") != std::string::npos)
        {
            ++startSymbols;
        }
        if (line.find(" T indexer_client::setLogFunction(") != std::string::npos)
        {
            ++setLogFunctionSymbols;
        }
        for (const char* pattern : denied)
        {
            if (line.find(pattern) != std::string::npos)
            {
                ++deniedLines;
                ADD_FAILURE() << "exported private-dependency symbol (" << pattern << "): " << line;
                break;
            }
        }
    }
    EXPECT_GT(startSymbols, 0u) << "indexer_client::RuntimeOwner::start is not exported";
    EXPECT_GT(setLogFunctionSymbols, 0u) << "indexer_client::setLogFunction is not exported (I56)";
    EXPECT_EQ(deniedLines, 0u);
}

// I45b: the .so is the production compilation, so not even its local symbols carry the test seams or the hooks. It
// needs the symbol table: the CI's coverage and ASAN jobs build Release `-O3 -s` (src/CMakeLists.txt:52), whose .so
// has none, so there the case is skipped; the TSAN job (Debug) and local Debug builds run it.
TEST(VisibilityTest, NoTestOnlySymbols)
{
    std::string all;
    ASSERT_TRUE(nmOfLibrary("", all)) << "nm failed: " << all;
    if (all.find(": no symbols") != std::string::npos)
    {
        GTEST_SKIP() << "stripped library (no symbol table): " << INDEXER_CLIENT_SO_PATH;
    }
    std::string line;
    const char* const testOnly[] = {"indexer_client::detail::seams", "indexer_client::testing_hooks"};
    std::size_t transportSymbols = 0;
    std::size_t testOnlyLines = 0;
    std::istringstream allLines(all);
    while (std::getline(allLines, line))
    {
        if (line.find("indexer_client::detail::") != std::string::npos && line.find("Transport") != std::string::npos)
        {
            ++transportSymbols;
        }
        for (const char* pattern : testOnly)
        {
            if (line.find(pattern) != std::string::npos)
            {
                ++testOnlyLines;
                ADD_FAILURE() << "test-only symbol in the production library (" << pattern << "): " << line;
                break;
            }
        }
    }
    EXPECT_GT(transportSymbols, 0u) << "nm saw no local symbol of the transport: the check would prove nothing";
    EXPECT_EQ(testOnlyLines, 0u);
}

namespace
{
    /// A loopback port with nothing listening: the probe's connect is refused at once.
    int closedPort()
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
        ::close(fd);
        return ntohs(address.sin_port);
    }

    /// One host (a closed port) and a one-hour probe: each start logs exactly the first round's WARN.
    class ClosedHostSource final : public indexer_client::IConfigSource
    {
    public:
        explicit ClosedHostSource(int port)
            : m_json(R"({"hosts":["http://127.0.0.1:)" + std::to_string(port) + R"("]})")
        {
        }

        std::optional<std::string> raw(std::string_view key) const override
        {
            const auto it = m_values.find(std::string(key));
            return it == m_values.end() ? std::nullopt : std::optional<std::string>(it->second);
        }

        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override
        {
            std::vector<std::string> keys;
            for (const auto& [key, value] : m_values)
            {
                if (key.compare(0, prefix.size(), prefix) == 0)
                {
                    keys.push_back(key);
                }
            }
            return keys;
        }

        std::string indexerSectionJson() const override
        {
            return m_json;
        }

        indexer_client::Credentials credentials() const override
        {
            return {"user", "pass"};
        }

    private:
        std::map<std::string, std::string> m_values {{"analysisd.indexer_client_network_threads", "1"},
                                                     {"analysisd.indexer_client_cpu_threads", "1"},
                                                     {"analysisd.indexer_client_probe_interval_ms", "3600000"}};
        std::string m_json;
    };

    /// The lines one log function received: {level, tag, formatted text}.
    struct Received final
    {
        struct Line final
        {
            int level;
            std::string tag;
            std::string text;
        };

        std::mutex mutex;
        std::vector<Line> lines;

        std::size_t size()
        {
            std::lock_guard<std::mutex> lock(mutex);
            return lines.size();
        }

        bool waitFor(std::size_t count)
        {
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (size() < count)
            {
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    return false;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return true;
        }
    };

    indexer_client::LogFunction logInto(const std::shared_ptr<Received>& received)
    {
        return [received](const int level,
                          const char* tag,
                          const char* /*file*/,
                          const int /*line*/,
                          const char* /*function*/,
                          const char* format,
                          va_list args)
        {
            va_list copy;
            va_copy(copy, args);
            char buffer[4096];
            std::vsnprintf(buffer, sizeof(buffer), format, copy);
            va_end(copy);
            std::lock_guard<std::mutex> lock(received->mutex);
            received->lines.push_back({level, tag ? tag : "", buffer});
        };
    }

    /// Starts the runtime on `source` and waits for `received` to hold `count` lines.
    void startAndWait(const indexer_client::IConfigSource& source,
                      const std::shared_ptr<Received>& received,
                      std::size_t count)
    {
        const auto started = indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, source);
        ASSERT_TRUE(started.ok()) << started.reason;
        EXPECT_TRUE(received->waitFor(count)) << "the first round's WARN never reached the log function";
    }
} // namespace

// I56: the library logs through the function setLogFunction() gives it, with its tag; while a runtime runs the call is
// ignored (the function stays) and counted as a usage error; after shutdown() it is accepted again.
TEST(VisibilityTest, SetLogFunctionRoutesLogs)
{
    ASSERT_FALSE(indexer_client::RuntimeOwner::running());
    const ClosedHostSource source(closedPort());
    auto first = std::make_shared<Received>();
    auto second = std::make_shared<Received>();
    indexer_client::setLogFunction(logInto(first));

    startAndWait(source, first, 1);
    {
        std::lock_guard<std::mutex> lock(first->mutex);
        ASSERT_EQ(first->lines.size(), 1u);
        EXPECT_EQ(first->lines[0].level, 2) << "WARN";
        EXPECT_EQ(first->lines[0].tag, "indexer-client");
        EXPECT_NE(first->lines[0].text.find("is no longer available. Reason: connect (curl 7)"), std::string::npos)
            << first->lines[0].text;
    }

    const auto usageErrors = indexer_client::detail::testing::usageErrors();
    indexer_client::setLogFunction(logInto(second)); // Runtime alive: ignored.
    EXPECT_EQ(indexer_client::detail::testing::usageErrors(), usageErrors + 1);
    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);

    startAndWait(source, first, 2); // The function did not change: the next runtime still logs into the first.
    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    EXPECT_EQ(second->size(), 0u) << "the call made with the runtime alive replaced the function";

    indexer_client::setLogFunction(logInto(second)); // No runtime: accepted.
    EXPECT_EQ(indexer_client::detail::testing::usageErrors(), usageErrors + 1);
    startAndWait(source, second, 1);
    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    EXPECT_EQ(first->size(), 2u);

    indexer_client::setLogFunction({}); // Empty silences the library.
    startAndWait(source, second, 1);
    EXPECT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    EXPECT_EQ(second->size(), 1u);
    EXPECT_EQ(first->size(), 2u);
}
