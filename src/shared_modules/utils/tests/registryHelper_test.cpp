/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */
#ifdef WIN32
#include "registryHelper_test.h"
#include "registryHelper.h"

constexpr auto CENTRAL_PROCESSOR_REGISTRY {"HARDWARE\\DESCRIPTION\\System\\CentralProcessor"};
constexpr auto CENTRAL_PROCESSOR_REGISTRY_0 {"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};

void RegistryUtilsTest::SetUp() {};

void RegistryUtilsTest::TearDown() {};

TEST_F(RegistryUtilsTest, RegistryString)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    const auto result {reg.string("ProcessorNameString")};
    EXPECT_FALSE(result.empty());
}

TEST_F(RegistryUtilsTest, RegistryStringNoThrow)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    std::string value;
    const auto result {reg.string("SomeWrongValue", value)};
    EXPECT_TRUE(value.empty());
    EXPECT_FALSE(result);
}

TEST_F(RegistryUtilsTest, RegistryDWORD)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    const auto result {reg.dword("~MHz")};
    EXPECT_NE(0u, result);
}

TEST_F(RegistryUtilsTest, RegistryDWORDNoThrow)
{
    DWORD value {0};
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    const auto result {reg.dword("SomeWrongValue", value)};
    EXPECT_FALSE(result);
}

TEST_F(RegistryUtilsTest, RegistryDWORDRejectsAStringValue)
{
    // A REG_SZ of three characters fits the DWORD buffer, so without a type check its bytes
    // are returned as a number: "123" reads back as 3355185. The value must be rejected and
    // the caller's variable left untouched.
    HKEY handler;
    const LPCTSTR subkey {TEXT("WazuhTest")};
    LPCTSTR value {TEXT("Test")};
    const char data[] {"123"};
    DWORD valueRead {0xABCD};

    auto result {RegCreateKeyEx(
        HKEY_CURRENT_USER, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &handler, nullptr)};
    EXPECT_EQ(ERROR_SUCCESS, result);

    result = RegSetValueEx(handler, value, 0, REG_SZ, reinterpret_cast<const BYTE*>(data), sizeof(data));
    EXPECT_EQ(ERROR_SUCCESS, result);

    Utils::Registry reg(HKEY_CURRENT_USER, subkey);
    EXPECT_FALSE(reg.dword(value, valueRead));
    EXPECT_EQ(0xABCD, valueRead);

    RegDeleteKeyEx(HKEY_CURRENT_USER, subkey, KEY_WOW64_64KEY, 0);
    RegCloseKey(handler);
}

TEST_F(RegistryUtilsTest, RegistryDWORDReadsARealDword)
{
    HKEY handler;
    const LPCTSTR subkey {TEXT("WazuhTest")};
    LPCTSTR value {TEXT("Test")};
    DWORD data {153600};
    DWORD valueRead {0};

    auto result {RegCreateKeyEx(
        HKEY_CURRENT_USER, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &handler, nullptr)};
    EXPECT_EQ(ERROR_SUCCESS, result);

    result = RegSetValueEx(handler, value, 0, REG_DWORD, reinterpret_cast<LPBYTE>(&data), sizeof(DWORD));
    EXPECT_EQ(ERROR_SUCCESS, result);

    Utils::Registry reg(HKEY_CURRENT_USER, subkey);
    EXPECT_TRUE(reg.dword(value, valueRead));
    EXPECT_EQ(data, valueRead);

    RegDeleteKeyEx(HKEY_CURRENT_USER, subkey, KEY_WOW64_64KEY, 0);
    RegCloseKey(handler);
}

TEST_F(RegistryUtilsTest, RegistryQWORD)
{
    HKEY handler;
    const LPCTSTR subkey {TEXT("WazuhTest")};
    LPCTSTR value {TEXT("Test")};
    ULONGLONG data {0xF00000000000000};
    ULONGLONG valueRead {0};

    auto result {RegCreateKeyEx(
        HKEY_CURRENT_USER, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &handler, nullptr)};
    EXPECT_EQ(ERROR_SUCCESS, result);

    result = RegSetValueEx(handler, value, 0, REG_QWORD, reinterpret_cast<LPBYTE>(&data), sizeof(ULONGLONG));
    EXPECT_EQ(ERROR_SUCCESS, result);

    Utils::Registry reg(HKEY_CURRENT_USER, subkey);
    result = reg.qword(value, valueRead);
    EXPECT_TRUE(result);
    EXPECT_EQ(data, valueRead);

    RegDeleteKeyEx(HKEY_CURRENT_USER, subkey, KEY_WOW64_64KEY, 0);
    RegCloseKey(handler);
}

TEST_F(RegistryUtilsTest, RegistryQWORDNoThrow)
{
    HKEY handler;
    const LPCTSTR subkey {TEXT("WazuhTest")};
    LPCTSTR value {TEXT("Test")};
    DWORD data {1};
    ULONGLONG valueRead {0};

    auto result {RegCreateKeyEx(
        HKEY_CURRENT_USER, subkey, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &handler, nullptr)};
    EXPECT_EQ(ERROR_SUCCESS, result);

    result = RegSetValueEx(handler, value, 0, REG_DWORD, reinterpret_cast<LPBYTE>(&data), sizeof(ULONGLONG));
    EXPECT_EQ(ERROR_SUCCESS, result);

    Utils::Registry reg(HKEY_CURRENT_USER, subkey);
    result = reg.qword(value, valueRead);
    EXPECT_FALSE(result);
    EXPECT_EQ(0u, valueRead);

    RegDeleteKeyEx(HKEY_CURRENT_USER, subkey, KEY_WOW64_64KEY, 0);
    RegCloseKey(handler);
}

TEST_F(RegistryUtilsTest, RegistryEnumerate)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY, KEY_ENUMERATE_SUB_KEYS | KEY_READ);
    const auto result {reg.enumerate()};
    EXPECT_NE(0u, result.size());
}

TEST_F(RegistryUtilsTest, RegistryEnumerateNoThrow)
{
    std::vector<std::string> values;
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0, KEY_ENUMERATE_SUB_KEYS | KEY_READ);
    reg.enumerate(values);
    EXPECT_EQ(0u, values.size());
}

TEST_F(RegistryUtilsTest, ExpandRegistryPathSkipsKeysNamedWithWildcards)
{
    HKEY handler;
    ASSERT_EQ(ERROR_SUCCESS,
              RegCreateKeyEx(HKEY_CURRENT_USER,
                             TEXT("WazuhTestExpand\\*\\InstallPath"),
                             0,
                             nullptr,
                             REG_OPTION_NON_VOLATILE,
                             KEY_ALL_ACCESS,
                             nullptr,
                             &handler,
                             nullptr));
    RegCloseKey(handler);
    ASSERT_EQ(ERROR_SUCCESS,
              RegCreateKeyEx(HKEY_CURRENT_USER,
                             TEXT("WazuhTestExpand\\3.12\\InstallPath"),
                             0,
                             nullptr,
                             REG_OPTION_NON_VOLATILE,
                             KEY_ALL_ACCESS,
                             nullptr,
                             &handler,
                             nullptr));
    RegCloseKey(handler);

    std::vector<std::string> keys;
    Utils::expandRegistryPath(HKEY_CURRENT_USER, "WazuhTestExpand\\*\\InstallPath", keys);

    EXPECT_EQ(std::vector<std::string> {"WazuhTestExpand\\3.12\\InstallPath"}, keys);

    RegDeleteTree(HKEY_CURRENT_USER, TEXT("WazuhTestExpand"));
}

#endif
