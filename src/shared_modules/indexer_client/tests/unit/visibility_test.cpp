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

#include <cstdio>
#include <sstream>
#include <string>

#include <sys/wait.h>

#include <gtest/gtest.h>

// RNF-1: the library exports its API and nothing from its private dependencies: asio (ASIO_DISABLE_VISIBILITY +
// -fvisibility=hidden), and libcurl, simdjson and OpenSSL once E2 links them (--exclude-libs,ALL).
TEST(VisibilityTest, ExportsApiAndNoAsio)
{
    const std::string command = std::string("nm -D --defined-only -C '") + INDEXER_CLIENT_SO_PATH + "' 2>&1";
    FILE* pipe = popen(command.c_str(), "r");
    ASSERT_NE(pipe, nullptr) << "cannot run: " << command;

    std::string output;
    char buffer[4096];
    std::size_t read = 0;
    while ((read = fread(buffer, 1, sizeof(buffer), pipe)) > 0)
    {
        output.append(buffer, read);
    }
    const int status = pclose(pipe);
    ASSERT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0) << "nm failed (" << status << "): " << output;
    ASSERT_FALSE(output.empty()) << "nm produced no output for " << INDEXER_CLIENT_SO_PATH;

    // Substrings of a demangled `nm` line that a private dependency would leave behind.
    const char* const denied[] = {"asio::", "curl_", "simdjson::", "SSL_", "CRYPTO_", "OPENSSL_"};

    std::size_t startSymbols = 0;
    std::size_t deniedLines = 0;
    std::istringstream lines(output);
    std::string line;
    while (std::getline(lines, line))
    {
        if (line.find("indexer_client::RuntimeOwner::start") != std::string::npos)
        {
            ++startSymbols;
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
    EXPECT_EQ(deniedLines, 0u);
}
