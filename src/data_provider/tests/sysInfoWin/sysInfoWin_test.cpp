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
#include "packages/packagesWindowsParserHelper.h"
#include "sysInfoWin_test.h"
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

// Tests for parseProcessCommandLine() — the UTF-16 to UTF-8 conversion and
// argument parsing logic used by the Windows process inventory.

// Empty input returns empty fields.
TEST_F(SysInfoWinTest, ParseCmdLineEmptyInput)
{
    const auto result = parseProcessCommandLine(L"");
    EXPECT_TRUE(result.cmd.empty());
    EXPECT_TRUE(result.argvs.empty());
}

// Simple executable path with no arguments.
TEST_F(SysInfoWinTest, ParseCmdLineNoArguments)
{
    const auto result = parseProcessCommandLine(L"C:\\Windows\\notepad.exe");
    EXPECT_EQ(result.cmd, "C:\\Windows\\notepad.exe");
    EXPECT_TRUE(result.argvs.empty());
}

// Executable with a single argument.
TEST_F(SysInfoWinTest, ParseCmdLineSingleArgument)
{
    const auto result = parseProcessCommandLine(L"app.exe --help");
    EXPECT_EQ(result.cmd, "app.exe --help");
    EXPECT_EQ(result.argvs, "--help");
}

// Executable with multiple arguments (svchost-style).
TEST_F(SysInfoWinTest, ParseCmdLineMultipleArguments)
{
    const auto result = parseProcessCommandLine(
                            L"C:\\Windows\\system32\\svchost.exe -k netsvcs -p");
    EXPECT_EQ(result.cmd, "C:\\Windows\\system32\\svchost.exe -k netsvcs -p");
    EXPECT_EQ(result.argvs, "-k netsvcs -p");
}

// Quoted executable path with spaces in the path.
TEST_F(SysInfoWinTest, ParseCmdLineQuotedPathWithSpaces)
{
    const auto result = parseProcessCommandLine(
                            L"\"C:\\Program Files\\My App\\app.exe\" --flag value");
    EXPECT_EQ(result.cmd, "\"C:\\Program Files\\My App\\app.exe\" --flag value");
    EXPECT_EQ(result.argvs, "--flag value");
}

// Quoted argument values are unquoted by CommandLineToArgvW.
TEST_F(SysInfoWinTest, ParseCmdLineQuotedArguments)
{
    const auto result = parseProcessCommandLine(
                            L"app.exe --name \"hello world\" --verbose");
    EXPECT_EQ(result.cmd, "app.exe --name \"hello world\" --verbose");
    EXPECT_EQ(result.argvs, "--name hello world --verbose");
}

// Unicode characters in the command line are properly converted to UTF-8.
TEST_F(SysInfoWinTest, ParseCmdLineUnicodeCharacters)
{
    // L"app.exe café" — é is U+00E9
    const auto result = parseProcessCommandLine(L"app.exe caf\u00E9");
    EXPECT_EQ(result.cmd, "app.exe caf\xC3\xA9");
    EXPECT_EQ(result.argvs, "caf\xC3\xA9");
}

// Command with many arguments preserves order and spacing.
TEST_F(SysInfoWinTest, ParseCmdLineManyArguments)
{
    const auto result = parseProcessCommandLine(L"cmd.exe /c dir /s /b /a-d");
    EXPECT_EQ(result.cmd, "cmd.exe /c dir /s /b /a-d");
    EXPECT_EQ(result.argvs, "/c dir /s /b /a-d");
}

// Calling the function twice with the same input produces the same result.
TEST_F(SysInfoWinTest, ParseCmdLineDeterministic)
{
    const std::wstring input = L"svchost.exe -k DcomLaunch -p";
    const auto result1 = parseProcessCommandLine(input);
    const auto result2 = parseProcessCommandLine(input);
    EXPECT_EQ(result1.cmd, result2.cmd);
    EXPECT_EQ(result1.argvs, result2.argvs);
}
