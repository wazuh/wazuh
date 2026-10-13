/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * The fixture itself: a FakeManager whose port is already taken must fail the test at once and
 * name the port, not probe for 300s and leave the test to fail as if the code under test hung
 * (#38329).
 */

#include "fakeManager.hpp"

#include <gtest/gtest-spi.h>
#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>

namespace
{
    // Below the ephemeral range and clear of every other component file (see facadeE2e's port map).
    constexpr uint16_t TAKEN_PORT = 24890;
} // namespace

TEST(FakeManagerComponentTest, ATakenPortFailsAtOnceAndNamesThePort)
{
    // A bound, non-listening socket: the probe is refused and the child's bind() gets EADDRINUSE.
    const int holder = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(holder, 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(TAKEN_PORT);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(0, bind(holder, reinterpret_cast<sockaddr*>(&address), sizeof(address)));

    const auto start = std::chrono::steady_clock::now();
    EXPECT_NONFATAL_FAILURE(FakeManager manager(TAKEN_PORT, ""), "is port 24890 already taken?");
    // Seconds even under Valgrind, where the forked child needs a few to reach bind(); not 300.
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds {120});

    close(holder);
}
