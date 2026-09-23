/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoProcessesMac_test.h"
#include "processes/processArgsParserMac.h"

namespace
{
    // Builds a buffer with the KERN_PROCARGS2 layout, padding the path to pointer alignment as the kernel does.
    std::vector<char> buildProcArgs(const int argc, const std::string& path, const std::vector<std::string>& strings)
    {
        constexpr size_t PTR_SIZE {sizeof(void*)};
        const size_t pathSize {path.size() + 1};
        const size_t alignedPathSize {(pathSize + PTR_SIZE - 1) / PTR_SIZE * PTR_SIZE};

        std::vector<char> buffer(sizeof(argc));
        std::memcpy(buffer.data(), &argc, sizeof(argc));
        buffer.insert(buffer.end(), path.begin(), path.end());
        buffer.insert(buffer.end(), alignedPathSize - path.size(), '\0');

        for (const auto& str : strings)
        {
            buffer.insert(buffer.end(), str.begin(), str.end());
            buffer.push_back('\0');
        }

        return buffer;
    }
}

TEST_F(SysInfoProcessesMacTest, parsesArgumentsAndSkipsEnvironment)
{
    const auto buffer {buildProcArgs(3, "/bin/sleep", {"sleep", "12345", "--flag value", "SECRET=1", "HOME=/root"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.executablePath, "/bin/sleep");
    EXPECT_EQ(result.argv, (std::vector<std::string> {"sleep", "12345", "--flag value"}));
}

TEST_F(SysInfoProcessesMacTest, keepsEmptyArguments)
{
    const auto buffer {buildProcArgs(3, "/bin/echo", {"echo", "", "x"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.argv, (std::vector<std::string> {"echo", "", "x"}));
}

TEST_F(SysInfoProcessesMacTest, emptyArgv0IsNotTreatedAsPadding)
{
    const auto buffer {buildProcArgs(2, "/bin/sleep", {"", "100", "AWS_SECRET=xyz"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.executablePath, "/bin/sleep");
    EXPECT_EQ(result.argv, (std::vector<std::string> {"", "100"}));

    const auto commandLine {buildProcessCommandLine("/bin/sleep", result)};
    EXPECT_EQ(commandLine.commandLine, "/bin/sleep 100");
    EXPECT_EQ(commandLine.args, "100");
    EXPECT_EQ(commandLine.argsCount, 1u);
}

TEST_F(SysInfoProcessesMacTest, leadingEmptyArgumentsWithAlignedPath)
{
    // "/bin/cat" plus its NUL is 9 bytes, so the path area is padded to 16.
    const auto buffer {buildProcArgs(3, "/bin/cat", {"", "", "file", "HOME=/root"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.argv, (std::vector<std::string> {"", "", "file"}));
}

TEST_F(SysInfoProcessesMacTest, pathFillingAlignmentHasNoPadding)
{
    // "/bin/ls" plus its NUL is exactly 8 bytes, so argv follows it directly.
    const auto buffer {buildProcArgs(2, "/bin/ls", {"", "-la", "PATH=/bin"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.argv, (std::vector<std::string> {"", "-la"}));
}

TEST_F(SysInfoProcessesMacTest, bufferEndsInsidePadding)
{
    // "/bin/zsh" plus its NUL is 9 bytes, padded to 16; cut the buffer after 10 of them.
    auto buffer {buildProcArgs(1, "/bin/zsh", {})};
    buffer.resize(sizeof(int) + std::string("/bin/zsh").size() + 2);
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.executablePath, "/bin/zsh");
    EXPECT_TRUE(result.argv.empty());
}

TEST_F(SysInfoProcessesMacTest, onlyProgramName)
{
    const auto buffer {buildProcArgs(1, "/usr/libexec/maild", {"maild"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.executablePath, "/usr/libexec/maild");
    EXPECT_EQ(result.argv, (std::vector<std::string> {"maild"}));
}

TEST_F(SysInfoProcessesMacTest, zeroArgc)
{
    const auto buffer {buildProcArgs(0, "/bin/sh", {"PATH=/bin"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.executablePath, "/bin/sh");
    EXPECT_TRUE(result.argv.empty());
}

TEST_F(SysInfoProcessesMacTest, argcLargerThanBuffer)
{
    const auto buffer {buildProcArgs(5, "/bin/ls", {"ls", "-la"})};
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.argv, (std::vector<std::string> {"ls", "-la"}));
}

TEST_F(SysInfoProcessesMacTest, unterminatedLastArgument)
{
    auto buffer {buildProcArgs(2, "/bin/cat", {"cat"})};
    const std::string partial {"/tmp/fi"};
    buffer.insert(buffer.end(), partial.begin(), partial.end());
    ProcessArgs result;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), result));
    EXPECT_EQ(result.argv, (std::vector<std::string> {"cat", "/tmp/fi"}));
}

TEST_F(SysInfoProcessesMacTest, invalidBuffers)
{
    ProcessArgs result;
    const int argc {1};

    EXPECT_FALSE(parseProcArgs2(nullptr, 0, result));
    EXPECT_FALSE(parseProcArgs2(reinterpret_cast<const char*>(&argc), sizeof(argc) - 1, result));

    const auto negativeArgc {buildProcArgs(-1, "/bin/ls", {})};
    EXPECT_FALSE(parseProcArgs2(negativeArgc.data(), negativeArgc.size(), result));

    auto unterminatedPath {buildProcArgs(1, "/bin/ls", {})};
    unterminatedPath.pop_back();
    EXPECT_FALSE(parseProcArgs2(unterminatedPath.data(), unterminatedPath.size(), result));
    EXPECT_TRUE(result.executablePath.empty());
    EXPECT_TRUE(result.argv.empty());
}

TEST_F(SysInfoProcessesMacTest, commandLineIncludesArguments)
{
    const ProcessArgs processArgs {"/usr/bin/log", {"log", "stream", "--style", "syslog", "--level", "info"}};
    const auto result {buildProcessCommandLine("/usr/bin/log", processArgs)};

    EXPECT_EQ(result.commandLine, "/usr/bin/log stream --style syslog --level info");
    EXPECT_EQ(result.args, "stream --style syslog --level info");
    EXPECT_EQ(result.argsCount, 5u);
}

TEST_F(SysInfoProcessesMacTest, commandLineUsesExecutablePathInsteadOfArgv0)
{
    const ProcessArgs processArgs {"/bin/sleep", {"sleep", "12345"}};
    const auto result {buildProcessCommandLine("/bin/sleep", processArgs)};

    EXPECT_EQ(result.commandLine, "/bin/sleep 12345");
    EXPECT_EQ(result.args, "12345");
    EXPECT_EQ(result.argsCount, 1u);
}

TEST_F(SysInfoProcessesMacTest, commandLineWithoutArguments)
{
    const ProcessArgs processArgs {"/usr/libexec/maild", {"maild"}};
    const auto result {buildProcessCommandLine("/usr/libexec/maild", processArgs)};

    EXPECT_EQ(result.commandLine, "/usr/libexec/maild");
    EXPECT_TRUE(result.args.empty());
    EXPECT_EQ(result.argsCount, 0u);
}

TEST_F(SysInfoProcessesMacTest, commandLineWhenArgumentsUnavailable)
{
    const std::string path {"/System/Library/CoreServices/Software Update.app/Contents/Resources/softwareupdated"};
    const auto result {buildProcessCommandLine(path, ProcessArgs {})};

    EXPECT_EQ(result.commandLine, path);
    EXPECT_TRUE(result.args.empty());
    EXPECT_EQ(result.argsCount, 0u);
}

TEST_F(SysInfoProcessesMacTest, commandLineSkipsEmptyArguments)
{
    const ProcessArgs processArgs {"/bin/echo", {"echo", "", "a", "", "b"}};
    const auto result {buildProcessCommandLine("/bin/echo", processArgs)};

    EXPECT_EQ(result.commandLine, "/bin/echo a b");
    EXPECT_EQ(result.args, "a b");
    EXPECT_EQ(result.argsCount, 2u);
}

TEST_F(SysInfoProcessesMacTest, commandLineKeepsArgumentWithSpaces)
{
    const ProcessArgs processArgs {"/bin/sh", {"sh", "-c", "curl -s http://x | sh"}};
    const auto result {buildProcessCommandLine("/bin/sh", processArgs)};

    EXPECT_EQ(result.commandLine, "/bin/sh -c curl -s http://x | sh");
    EXPECT_EQ(result.args, "-c curl -s http://x | sh");
    EXPECT_EQ(result.argsCount, 2u);
}

TEST_F(SysInfoProcessesMacTest, commandLineFallsBackToArgumentAreaPath)
{
    const ProcessArgs processArgs {"/usr/sbin/cfprefsd", {"cfprefsd", "daemon"}};
    const auto result {buildProcessCommandLine("", processArgs)};

    EXPECT_EQ(result.commandLine, "/usr/sbin/cfprefsd daemon");
    EXPECT_EQ(result.args, "daemon");
    EXPECT_EQ(result.argsCount, 1u);
}

TEST_F(SysInfoProcessesMacTest, commandLineWithoutAnyPath)
{
    const ProcessArgs processArgs {"", {"daemon", "--foreground"}};
    const auto result {buildProcessCommandLine("", processArgs)};

    EXPECT_EQ(result.commandLine, "--foreground");
    EXPECT_EQ(result.args, "--foreground");
    EXPECT_EQ(result.argsCount, 1u);

    const auto empty {buildProcessCommandLine("", ProcessArgs {})};
    EXPECT_TRUE(empty.commandLine.empty());
    EXPECT_TRUE(empty.args.empty());
    EXPECT_EQ(empty.argsCount, 0u);
}

TEST_F(SysInfoProcessesMacTest, parsedBufferToCommandLine)
{
    const auto buffer {buildProcArgs(3, "/usr/bin/log", {"log", "stream", "--predicate (process == \"sudo\")", "TERM=xterm"})};
    ProcessArgs processArgs;

    ASSERT_TRUE(parseProcArgs2(buffer.data(), buffer.size(), processArgs));
    const auto result {buildProcessCommandLine("/usr/bin/log", processArgs)};

    EXPECT_EQ(result.commandLine, "/usr/bin/log stream --predicate (process == \"sudo\")");
    EXPECT_EQ(result.argsCount, 2u);
}
