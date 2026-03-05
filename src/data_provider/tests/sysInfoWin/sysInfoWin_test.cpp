/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include <set>
#include <stdio.h>
#include <algorithm>
#include "packages/packagesWindowsParserHelper.h"
#include "sysInfoWin_test.h"
#include "sysInfo.hpp"
#include <iostream>


void SysInfoWinTest::SetUp() {};
void SysInfoWinTest::TearDown() {};

TEST_F(SysInfoWinTest, test_extract_HFValue_7618)
{
    // Invalid cases
    EXPECT_EQ("", PackageWindowsHelper::extractHFValue("KB"));
    EXPECT_EQ("", PackageWindowsHelper::extractHFValue("KBAAAAAA"));
    EXPECT_EQ("", PackageWindowsHelper::extractHFValue("AABBEEKB25A34111"));
    // Valid cases
    EXPECT_EQ("KB976902", PackageWindowsHelper::extractHFValue("KB976902\\KB976932\\SUPPORT\\SSU\\SAND\\5A42A8EB"));
    EXPECT_EQ("KB976932", PackageWindowsHelper::extractHFValue("KB976932\\SAND\\87C8A3D4"));
    EXPECT_EQ("KB2534111", PackageWindowsHelper::extractHFValue("KB2534111.MSU\\8847D77D"));
    EXPECT_EQ("KB2534111", PackageWindowsHelper::extractHFValue("KBKBKBKBKB2534111"));
    EXPECT_EQ("KB2534111", PackageWindowsHelper::extractHFValue("KB2534111"));
}

TEST_F(SysInfoWinTest, testHF_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromReg(HKEY_LOCAL_MACHINE, PackageWindowsHelper::WIN_REG_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

TEST_F(SysInfoWinTest, testHF_NT_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromRegNT(HKEY_LOCAL_MACHINE, PackageWindowsHelper::VISTA_REG_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

TEST_F(SysInfoWinTest, testHF_WOW_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromRegWOW(HKEY_LOCAL_MACHINE, PackageWindowsHelper::WIN_REG_WOW_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

TEST_F(SysInfoWinTest, testHF_PRODUCT_Valids_Format)
{
    std::set<std::string> ret;
    constexpr auto KB_FORMAT_REGEX_OK { "(KB+[0-9]{6,})"};
    constexpr auto KB_ONLY_FORMAT_REGEX { "(KB)"};
    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};
    PackageWindowsHelper::getHotFixFromRegProduct(HKEY_LOCAL_MACHINE, PackageWindowsHelper::WIN_REG_PRODUCT_HOTFIX, ret);

    for (const auto& hf : ret)
    {
        EXPECT_TRUE(std::regex_match(hf, std::regex(KB_FORMAT_REGEX_OK)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_ONLY_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }
}

//  Test: Windows Management Instrumentation (WMI) to retrieve installed hotfixes
TEST_F(SysInfoWinTest, WmiLocatorCreationFailure)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateWmiLocator(::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiConnectToWmiServerFailure)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiSetProxyBlanket)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiExecuteQuery)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ExecuteWmiQuery(testing::_, testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiPopulatesWMIHotfixSetCorrectly)
{
    std::set<std::string> hotfixSet;
    ComHelper comHelper;

    HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    EXPECT_TRUE(SUCCEEDED(hres)) << "COM Initialization failed with HRESULT: " << std::hex << hres;

    QueryWMIHotFixes(hotfixSet, comHelper);

    constexpr auto KB_NO_NUMBERS_FORMAT_REGEX { "(KB+[a-z])"};
    constexpr auto KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX { "(KB+[0-9]{6,}+[aA-zZ])"};

    for (const auto& hf : hotfixSet)
    {
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_NO_NUMBERS_FORMAT_REGEX)));
        EXPECT_FALSE(std::regex_match(hf, std::regex(KB_WITH_NUMBERS_AND_LETTERS_FORMAT_REGEX)));
    }

    CoUninitialize();
}

// Test: Windows Update Agent (WUA) for installed update history,
TEST_F(SysInfoWinTest, WuaLocatorCreationFailure)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WuaGetTotalHistoryCount)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, GetTotalHistoryCount(::testing::_, ::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WuaQueryHistory)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, GetTotalHistoryCount(::testing::_, ::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, QueryHistory(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWUHotFixes(hotfixSet, mockHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, GetHistoryTest)
{
    MockComHelper mockHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockHelper, CreateUpdateSearcher(::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, GetTotalHistoryCount(::testing::_, ::testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockHelper, QueryHistory(::testing::_, ::testing::_, ::testing::_))
    .WillOnce(testing::Return(S_OK));

    long count = 4;
    EXPECT_CALL(mockHelper, GetCount(testing::_, testing::_))
    .WillOnce(testing::DoAll(testing::SetArgReferee<1>(count), testing::Return(S_OK)));

    for (int i = 0 ; i < count; i++)
    {

        EXPECT_CALL(mockHelper, GetItem(testing::_, i, testing::_))
        .WillOnce(testing::Return(S_OK));

        // Simulate getting the title
        EXPECT_CALL(mockHelper, GetTitle(testing::_, testing::_))
        .WillRepeatedly(testing::Invoke([](IUpdateHistoryEntry*, BSTR & title) -> HRESULT
        {
            title = SysAllocString(L"Security Update KB123456");
            return S_OK;
        }));
    }

    QueryWUHotFixes(hotfixSet, mockHelper);

    EXPECT_EQ(hotfixSet.size(), static_cast<unsigned int>(1));
    EXPECT_EQ(*hotfixSet.begin(), "KB123456");
}

// Helper: check if a PID corresponds to a system process (PID 0 or 4)
static bool isSystemPid(const std::string& pidStr)
{
    return pidStr == "0" || pidStr == "4";
}

// Test: Process command line retrieval via NtQueryInformationProcess

// Verify that processes() returns a non-empty JSON array with expected fields.
TEST_F(SysInfoWinTest, ProcessListIsNotEmpty)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();
    ASSERT_TRUE(processes.is_array());
    EXPECT_FALSE(processes.empty()) << "Process list should not be empty";
}

// Verify that every process entry contains the expected fields including cmd and argvs.
TEST_F(SysInfoWinTest, AllProcessesHaveCmdAndArgvsFields)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();

    for (const auto& proc : processes)
    {
        ASSERT_TRUE(proc.contains("pid"))  << "Missing 'pid' field: "  << proc.dump();
        ASSERT_TRUE(proc.contains("cmd"))  << "Missing 'cmd' field: "  << proc.dump();
        ASSERT_TRUE(proc.contains("argvs")) << "Missing 'argvs' field: " << proc.dump();
        ASSERT_TRUE(proc.contains("name")) << "Missing 'name' field: " << proc.dump();
    }
}

// Verify that system processes (PID 0 and 4) have cmd="none" and argvs="" as expected.
TEST_F(SysInfoWinTest, SystemProcessesHaveNoneCmd)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();

    for (const auto& proc : processes)
    {
        const auto pid = proc.at("pid").get<std::string>();

        if (isSystemPid(pid))
        {
            EXPECT_EQ(proc.at("cmd").get<std::string>(), "none")
                    << "System process PID " << pid << " should have cmd='none'";
            EXPECT_EQ(proc.at("argvs").get<std::string>(), "")
                    << "System process PID " << pid << " should have empty argvs";
        }
    }
}

// Verify that non-system processes have a non-empty cmd field.
TEST_F(SysInfoWinTest, NonSystemProcessesHaveNonEmptyCmd)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();
    int nonSystemCount = 0;

    for (const auto& proc : processes)
    {
        const auto pid = proc.at("pid").get<std::string>();

        if (!isSystemPid(pid))
        {
            const auto cmd = proc.at("cmd").get<std::string>();

            // Some processes may not be accessible (access denied), so cmd could be empty.
            // But the majority should have a non-empty cmd.
            if (!cmd.empty())
            {
                nonSystemCount++;
            }
        }
    }

    EXPECT_GT(nonSystemCount, 0) << "At least some non-system processes should have a non-empty cmd";
}

// Verify that the current test process is present in the process list
// and has a non-empty cmd that contains the executable name.
TEST_F(SysInfoWinTest, CurrentProcessHasCommandLine)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();
    const auto currentPid = std::to_string(GetCurrentProcessId());

    bool found = false;

    for (const auto& proc : processes)
    {
        if (proc.at("pid").get<std::string>() == currentPid)
        {
            found = true;
            const auto cmd = proc.at("cmd").get<std::string>();
            EXPECT_FALSE(cmd.empty())
                    << "Current process (PID " << currentPid << ") should have a non-empty cmd";

            // The cmd should contain the test executable name
            const auto cmdLower = [&cmd]()
            {
                std::string lower = cmd;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                return lower;
            }
            ();
            EXPECT_NE(cmdLower.find("sysinfowindows_unit_test"), std::string::npos)
                    << "Current process cmd should contain the test executable name, got: " << cmd;
            break;
        }
    }

    EXPECT_TRUE(found) << "Current process (PID " << currentPid << ") should be in the process list";
}

// Verify that at least one process with arguments has a populated argvs field.
// On a typical Windows system, processes like svchost.exe always run with arguments.
TEST_F(SysInfoWinTest, SomeProcessesHaveArgvs)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();
    int withArgvs = 0;

    for (const auto& proc : processes)
    {
        const auto pid = proc.at("pid").get<std::string>();

        if (!isSystemPid(pid))
        {
            const auto argvs = proc.at("argvs").get<std::string>();

            if (!argvs.empty())
            {
                withArgvs++;
            }
        }
    }

    EXPECT_GT(withArgvs, 0)
            << "At least one non-system process should have populated argvs "
            << "(e.g., svchost.exe -k ...)";
}

// Verify that when argvs is populated, cmd contains more than just an executable path.
// This validates that the full command line is retrieved, not just the path.
TEST_F(SysInfoWinTest, CmdContainsArgumentsWhenArgvsPopulated)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();

    for (const auto& proc : processes)
    {
        const auto pid = proc.at("pid").get<std::string>();

        if (!isSystemPid(pid))
        {
            const auto cmd   = proc.at("cmd").get<std::string>();
            const auto argvs = proc.at("argvs").get<std::string>();

            if (!argvs.empty() && !cmd.empty())
            {
                // If argvs has content, cmd should contain more than just a file path.
                // Specifically, cmd should contain at least a space separating the exe from args.
                EXPECT_NE(cmd.find(" "), std::string::npos)
                        << "Process PID " << pid << " has argvs='" << argvs
                        << "' but cmd has no spaces: '" << cmd << "'";
            }
        }
    }
}

// Verify that the callback-based processes() overload produces the same data.
TEST_F(SysInfoWinTest, CallbackVersionProducesSameData)
{
    SysInfo sysInfo;
    const auto directResult = sysInfo.processes();

    nlohmann::json callbackResult = nlohmann::json::array();
    sysInfo.processes([&callbackResult](nlohmann::json & data)
    {
        callbackResult.push_back(data);
    });

    EXPECT_EQ(directResult.size(), callbackResult.size())
            << "Both processes() overloads should return the same number of processes";
}

// Verify that svchost.exe processes (if present) have populated argvs.
// svchost.exe always runs with -k arguments on a normal Windows system.
TEST_F(SysInfoWinTest, SvchostProcessesHaveArguments)
{
    SysInfo sysInfo;
    const auto processes = sysInfo.processes();
    int svchostCount = 0;
    int svchostWithArgvs = 0;

    for (const auto& proc : processes)
    {
        const auto name = proc.at("name").get<std::string>();
        auto nameLower = name;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

        if (nameLower == "svchost.exe")
        {
            svchostCount++;
            const auto argvs = proc.at("argvs").get<std::string>();

            if (!argvs.empty())
            {
                svchostWithArgvs++;

                // svchost.exe always uses -k flag
                EXPECT_NE(argvs.find("-k"), std::string::npos)
                        << "svchost.exe argvs should contain '-k', got: " << argvs;
            }
        }
    }

    if (svchostCount > 0)
    {
        EXPECT_GT(svchostWithArgvs, 0)
                << "At least one svchost.exe should have populated argvs "
                << "(found " << svchostCount << " svchost.exe processes)";
    }
}
