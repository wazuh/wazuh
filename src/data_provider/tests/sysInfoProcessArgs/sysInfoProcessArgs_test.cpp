/*
 * Wazuh SYSINFO
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "processes/processArgs.h"

using ProcessArgList = std::vector<std::string>;

// Arguments with commas or spaces stay single elements; argv[0] is not an argument.
TEST(SysInfoProcessArgsTest, FromArgvKeepsArgumentBoundaries)
{
    const char* argv[] {"/sbin/agetty", "-o", "-p -- \\u", "--keep-baud", "115200,57600,38400,9600", "-", "vt220", nullptr};

    EXPECT_EQ(ProcessArgs::fromArgv(argv),
              (ProcessArgList {"-o", "-p -- \\u", "--keep-baud", "115200,57600,38400,9600", "-", "vt220"}));
}

// Empty arguments are skipped, matching args_count on every platform.
TEST(SysInfoProcessArgsTest, FromArgvSkipsEmptyArguments)
{
    const char* argv[] {"python3", "", "a,b", "", "c d", nullptr};

    EXPECT_EQ(ProcessArgs::fromArgv(argv), (ProcessArgList {"a,b", "c d"}));
}

// No cmdline (kernel threads) or only the executable gives no arguments.
TEST(SysInfoProcessArgsTest, FromArgvWithoutArguments)
{
    const char* onlyExecutable[] {"/usr/sbin/sshd", nullptr};
    const char* empty[] {nullptr};

    EXPECT_TRUE(ProcessArgs::fromArgv(nullptr).empty());
    EXPECT_TRUE(ProcessArgs::fromArgv(empty).empty());
    EXPECT_TRUE(ProcessArgs::fromArgv(onlyExecutable).empty());
}

// The encoded value is a JSON array string that decodes back to the same elements.
TEST(SysInfoProcessArgsTest, EncodeIsJsonArrayString)
{
    const ProcessArgList args {"a,b", "c d", "say \"hi\""};
    const auto encoded {ProcessArgs::encode(args)};

    EXPECT_EQ(encoded, R"(["a,b","c d","say \"hi\""])");
    EXPECT_EQ(nlohmann::json::parse(encoded).get<ProcessArgList>(), args);
}

// No arguments encode as an empty string, so the field reaches the document as null.
TEST(SysInfoProcessArgsTest, EncodeEmptyIsEmptyString)
{
    EXPECT_EQ(ProcessArgs::encode({}), "");
}

// Invalid UTF-8 is replaced instead of throwing, so one argument cannot abort the scan.
TEST(SysInfoProcessArgsTest, EncodeInvalidUtf8DoesNotThrow)
{
    std::string encoded;
    EXPECT_NO_THROW(encoded = ProcessArgs::encode({"ok", "bad\xff"}));
    EXPECT_EQ(nlohmann::json::parse(encoded).size(), 2u);
}

// The command line is the executable followed by the arguments.
TEST(SysInfoProcessArgsTest, CommandLineJoinsExecutableAndArguments)
{
    EXPECT_EQ(ProcessArgs::commandLine("/usr/bin/python3", {"-c", "a,b", "c d"}), "/usr/bin/python3 -c a,b c d");
    EXPECT_EQ(ProcessArgs::commandLine("/usr/sbin/sshd", {}), "/usr/sbin/sshd");
    EXPECT_EQ(ProcessArgs::commandLine("", {}), "");
}
