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
#include <cstring>
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

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_, testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

TEST_F(SysInfoWinTest, WmiSetProxyBlanket)
{
    MockComHelper mockComHelper;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_, testing::_))
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

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ExecuteWmiQuery(testing::_, testing::_))
    .WillOnce(testing::Return(E_FAIL));

    EXPECT_THROW(QueryWMIHotFixes(hotfixSet, mockComHelper), std::runtime_error);
}

// Regression test for issue #38370: a Winmgmt that never signals end-of-enumeration
// (previously: Next(WBEM_INFINITE, ...) blocking the syscollector worker thread forever)
// must make QueryWMIHotFixes give up and throw once the overall ceiling is exceeded,
// not hang. Tiny timeouts keep this test fast instead of waiting on the multi-second
// production defaults.
TEST_F(SysInfoWinTest, WmiHotfixEnumerationTimeoutThrows)
{
    MockComHelper mockComHelper;
    MockEnumWbemClassObject mockEnum;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ExecuteWmiQuery(testing::_, testing::_))
    .WillOnce(testing::DoAll(
                  testing::SetArgReferee<1>(&mockEnum),
                  testing::Return(S_OK)));

    // Every call times out with no object ready -- never signals completion
    // (uReturn == 0 with a non-timeout HRESULT), so the only way out is the new
    // cumulative-elapsed-time ceiling.
    EXPECT_CALL(mockEnum, Next(testing::_, testing::_, testing::_, testing::_))
    .WillRepeatedly(testing::Return(WBEM_S_TIMEDOUT));

    EXPECT_THROW(QueryWMIHotFixesBounded(hotfixSet, mockComHelper, /*perCallTimeoutMs*/ 1, /*overallTimeoutMs*/ 5,
                                         WMI_CONNECT_MAX_WAIT_MS),
                 std::runtime_error);
}

// Regression test: a hard COM failure from Next() (e.g. a dropped remote WMI transport
// mid-enumeration) must make QueryWMIHotFixes give up and throw immediately, not fall
// through to the uReturn==0 check with stale state from a prior iteration.
TEST_F(SysInfoWinTest, WmiHotfixEnumerationNextFailureThrows)
{
    MockComHelper mockComHelper;
    MockEnumWbemClassObject mockEnum;
    std::set<std::string> hotfixSet;

    EXPECT_CALL(mockComHelper, CreateWmiLocator(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ConnectToWmiServer(testing::_, testing::_, testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, SetProxyBlanket(testing::_))
    .WillOnce(testing::Return(S_OK));

    EXPECT_CALL(mockComHelper, ExecuteWmiQuery(testing::_, testing::_))
    .WillOnce(testing::DoAll(
                  testing::SetArgReferee<1>(&mockEnum),
                  testing::Return(S_OK)));

    EXPECT_CALL(mockEnum, Next(testing::_, testing::_, testing::_, testing::_))
    .WillOnce(testing::Return(WBEM_E_TRANSPORT_FAILURE));

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


// Tests for buildProcessSnapshotRecord() — the record the Windows process inventory
// emits from the snapshot entry alone, with no handle on the process.

namespace
{
    PROCESSENTRY32 makeProcessEntry(const DWORD pid, const DWORD parentPid, const char* exeFile)
    {
        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(PROCESSENTRY32);
        entry.th32ProcessID = pid;
        entry.th32ParentProcessID = parentPid;
        std::strncpy(entry.szExeFile, exeFile, sizeof(entry.szExeFile) - 1);
        return entry;
    }
}

// A regular entry yields the snapshot fields and nothing that needs a handle.
TEST_F(SysInfoWinTest, BuildProcessSnapshotRecordNormalEntry)
{
    const auto record = buildProcessSnapshotRecord(makeProcessEntry(1234, 5678, "notepad.exe"));

    EXPECT_EQ(record.at("name").get<std::string>(), "notepad.exe");
    EXPECT_EQ(record.at("pid").get<std::string>(), "1234");
    EXPECT_EQ(record.at("parent_pid").get<DWORD>(), static_cast<DWORD>(5678));
    EXPECT_FALSE(record.contains("command_line"));
    EXPECT_FALSE(record.contains("args"));
    EXPECT_FALSE(record.contains("args_count"));
    EXPECT_FALSE(record.contains("stime"));
    EXPECT_FALSE(record.contains("utime"));
    EXPECT_FALSE(record.contains("start"));
}

// Pid 0 is named from the snapshot path and must not carry the self-referential parent.
TEST_F(SysInfoWinTest, BuildProcessSnapshotRecordSystemIdleProcess)
{
    const auto record = buildProcessSnapshotRecord(makeProcessEntry(0, 0, "[System Process]"));

    EXPECT_EQ(record.at("name").get<std::string>(), "System Idle Process");
    EXPECT_EQ(record.at("pid").get<std::string>(), "0");
    EXPECT_FALSE(record.contains("parent_pid"));
}

// Pid 4 is the kernel process, named from the snapshot path as well, and keeps its parent.
TEST_F(SysInfoWinTest, BuildProcessSnapshotRecordSystemProcess)
{
    const auto record = buildProcessSnapshotRecord(makeProcessEntry(4, 0, "System"));

    EXPECT_EQ(record.at("name").get<std::string>(), "System");
    EXPECT_EQ(record.at("pid").get<std::string>(), "4");
    EXPECT_EQ(record.at("parent_pid").get<DWORD>(), static_cast<DWORD>(0));
}

// szExeFile arrives in the ANSI code page and has to come out as UTF-8. Skipped where the
// active code page cannot represent the name, which would make the expectation unreachable.
TEST_F(SysInfoWinTest, BuildProcessSnapshotRecordNonAsciiName)
{
    // L"café.exe" — é is U+00E9
    char ansiName[MAX_PATH] {};
    BOOL usedDefaultChar = FALSE;
    const int converted = WideCharToMultiByte(CP_ACP, 0, L"caf\u00E9.exe", -1,
                                              ansiName, MAX_PATH, nullptr, &usedDefaultChar);

    if (0 == converted || usedDefaultChar)
    {
        GTEST_SKIP() << "The active ANSI code page cannot represent the test name.";
    }

    const auto record = buildProcessSnapshotRecord(makeProcessEntry(1111, 1, ansiName));

    EXPECT_EQ(record.at("name").get<std::string>(), "caf\xC3\xA9.exe");
}


// Tests for buildProcessRecord() — the merge of the snapshot fields with the fields that
// need a process handle, which is where the reported defect lived.

// No handle fields is the case where OpenProcess failed. Producing an empty record here is
// what removed protected processes such as lsass.exe from the inventory.
TEST_F(SysInfoWinTest, BuildProcessRecordWithoutHandleFieldsKeepsSnapshotFields)
{
    const auto record = buildProcessRecord(makeProcessEntry(660, 552, "lsass.exe"), nlohmann::json::object());

    EXPECT_FALSE(record.empty());
    EXPECT_EQ(record.at("name").get<std::string>(), "lsass.exe");
    EXPECT_EQ(record.at("pid").get<std::string>(), "660");
    EXPECT_EQ(record.at("parent_pid").get<DWORD>(), static_cast<DWORD>(552));
    EXPECT_FALSE(record.contains("start"));
    EXPECT_FALSE(record.contains("command_line"));
}

// The handle-derived fields are overlaid on the snapshot ones: both survive.
TEST_F(SysInfoWinTest, BuildProcessRecordOverlaysHandleFields)
{
    const nlohmann::json handleFields
    {
        {"start", "2026-09-11T00:00:00Z"},
        {"stime", 12},
        {"utime", 34},
        {"command_line", "C:\\Windows\\system32\\svchost.exe -k netsvcs"}
    };
    const auto record = buildProcessRecord(makeProcessEntry(1000, 660, "svchost.exe"), handleFields);

    EXPECT_EQ(record.at("name").get<std::string>(), "svchost.exe");
    EXPECT_EQ(record.at("pid").get<std::string>(), "1000");
    EXPECT_EQ(record.at("parent_pid").get<DWORD>(), static_cast<DWORD>(660));
    EXPECT_EQ(record.at("start").get<std::string>(), "2026-09-11T00:00:00Z");
    EXPECT_EQ(record.at("stime").get<int>(), 12);
    EXPECT_EQ(record.at("utime").get<int>(), 34);
    EXPECT_EQ(record.at("command_line").get<std::string>(), "C:\\Windows\\system32\\svchost.exe -k netsvcs");
}

// A default-constructed nlohmann::json is a null, not an empty object, and it is what the
// production caller hands over when no handle opened. Overlaying it must not throw.
TEST_F(SysInfoWinTest, BuildProcessRecordWithDefaultConstructedHandleFields)
{
    const auto record = buildProcessRecord(makeProcessEntry(0, 0, "[System Process]"), nlohmann::json {});

    EXPECT_EQ(record.at("name").get<std::string>(), "System Idle Process");
    EXPECT_EQ(record.at("pid").get<std::string>(), "0");
    EXPECT_FALSE(record.contains("parent_pid"));
    EXPECT_FALSE(record.contains("start"));
}

// The GetProcessTimes-failed path: a command line but no times.
TEST_F(SysInfoWinTest, BuildProcessRecordWithPartialHandleFields)
{
    const nlohmann::json partialHandleFields {{"command_line", "none"}, {"args", ""}, {"args_count", 0}};
    const auto record = buildProcessRecord(makeProcessEntry(4, 0, "System"), partialHandleFields);

    EXPECT_EQ(record.at("name").get<std::string>(), "System");
    EXPECT_EQ(record.at("command_line").get<std::string>(), "none");
    EXPECT_FALSE(record.contains("start"));
    EXPECT_FALSE(record.contains("stime"));
    EXPECT_FALSE(record.contains("utime"));
}
