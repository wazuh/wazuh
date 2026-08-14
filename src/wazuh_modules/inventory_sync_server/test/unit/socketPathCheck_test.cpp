/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "common/socketPathCheck.hpp"

#include <gtest/gtest.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using invsync::common::socketPathIsUsable;

namespace
{
    std::string uniqueTempPath(const char* tag)
    {
        static int counter {0};
        return "/tmp/iss_spc_" + std::string {tag} + "_" + std::to_string(::getpid()) + "_" + std::to_string(counter++);
    }
} // namespace

/**
 * These decide whether the module is allowed to start at all: a false answer is FATAL and takes
 * modulesd down with it, rather than being retried. So each branch needs to be exactly right -- a false
 * negative refuses to boot a healthy manager, and a false positive puts us back to logging an ERROR
 * every 60 s forever with no ingress.
 */
TEST(SocketPathCheckTest, APathInAnExistingWritableDirectoryIsUsable)
{
    std::string reason {"untouched"};
    EXPECT_TRUE(socketPathIsUsable(uniqueTempPath("ok"), reason));
    EXPECT_EQ("untouched", reason) << "the reason must not be written on success";
}

TEST(SocketPathCheckTest, AnEmptyPathIsRejected)
{
    std::string reason;
    EXPECT_FALSE(socketPathIsUsable("", reason));
    EXPECT_FALSE(reason.empty());
}

// sockaddr_un::sun_path is famously short, and asio's own failure for an over-long path is opaque.
TEST(SocketPathCheckTest, APathOverTheSunPathLimitIsRejectedAndSaysSo)
{
    constexpr std::size_t SUN_PATH_MAX {sizeof(::sockaddr_un::sun_path)};
    const std::string tooLong = "/tmp/" + std::string(SUN_PATH_MAX, 'x');

    std::string reason;
    EXPECT_FALSE(socketPathIsUsable(tooLong, reason));
    EXPECT_NE(std::string::npos, reason.find("limit for Unix domain sockets")) << reason;
}

TEST(SocketPathCheckTest, AMissingParentDirectoryIsRejectedAndNamesIt)
{
    std::string reason;
    EXPECT_FALSE(socketPathIsUsable("/proc/self/does-not-exist/inventory-sync.sock", reason));
    EXPECT_NE(std::string::npos, reason.find("does-not-exist")) << reason;
}

// The check must refuse rather than plan to delete: a typo in a path must never cost an operator a file.
TEST(SocketPathCheckTest, ANonSocketFileAlreadyAtThePathIsRejected)
{
    const auto path = uniqueTempPath("regular");
    {
        std::ofstream file {path};
        file << "not a socket";
    }

    std::string reason;
    EXPECT_FALSE(socketPathIsUsable(path, reason));
    EXPECT_NE(std::string::npos, reason.find("not a socket")) << reason;

    std::filesystem::remove(path);
}

/**
 * A stale SOCKET is the one pre-existing file that IS acceptable: bindAcceptor() unlinks it, which is
 * what lets the module come back after an unclean shutdown. Rejecting it here would make an unclean
 * stop turn into a manager that refuses to boot.
 */
TEST(SocketPathCheckTest, AStaleSocketAtThePathIsAcceptedBecauseBindUnlinksIt)
{
    const auto path = uniqueTempPath("stale");

    // A real socket file, bound and then abandoned without unlinking.
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0);
    ::sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::snprintf(address.sun_path, sizeof(address.sun_path), "%s", path.c_str());
    ASSERT_EQ(0, ::bind(fd, reinterpret_cast<::sockaddr*>(&address), sizeof(address)));
    ::close(fd);

    ASSERT_TRUE(std::filesystem::is_socket(path));

    std::string reason;
    EXPECT_TRUE(socketPathIsUsable(path, reason)) << reason;

    std::filesystem::remove(path);
}

// A bare filename resolves against the process's cwd, which is how modulesd actually runs (it chdir()s
// to the install dir and the configured path is relative).
TEST(SocketPathCheckTest, ARelativePathIsCheckedAgainstTheCurrentDirectory)
{
    std::string reason;
    EXPECT_TRUE(socketPathIsUsable("inventory-sync.sock", reason)) << reason;
}
