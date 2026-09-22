/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WIN32
#include "registryHelper_test.h"
#include "registryHelper.h"

constexpr auto CENTRAL_PROCESSOR_REGISTRY {"HARDWARE\\DESCRIPTION\\System\\CentralProcessor"};
constexpr auto CENTRAL_PROCESSOR_REGISTRY_0 {"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};
constexpr auto UTF8_TEST_SUBKEY {"WazuhTestUtf8"};
constexpr auto UTF8_TEST_SUBKEY_W {L"WazuhTestUtf8"};
constexpr auto UTF8_TEST_VALUE {"DisplayName"};
constexpr auto UTF8_TEST_VALUE_W {L"DisplayName"};

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

/*
 * Writes a REG_SZ value holding UTF-16 data, so the tests below can read back data that the
 * system ANSI code page cannot represent.
 */
static bool writeWideTestValue(const std::wstring& data)
{
    HKEY handler {nullptr};

    if (RegCreateKeyExW(HKEY_CURRENT_USER, UTF8_TEST_SUBKEY_W, 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS,
                        nullptr, &handler, nullptr) != ERROR_SUCCESS)
    {
        return false;
    }

    const auto result {RegSetValueExW(handler, UTF8_TEST_VALUE_W, 0, REG_SZ,
                                      reinterpret_cast<const BYTE*>(data.c_str()),
                                      static_cast<DWORD>((data.size() + 1) * sizeof(wchar_t)))};
    RegCloseKey(handler);

    return ERROR_SUCCESS == result;
}

TEST_F(RegistryUtilsTest, RegistryStringUtf8KeepsCharactersOutsideTheSystemCodePage)
{
    /*
     * U+6DF1 U+5733 (Han), U+6C49 (simplified-only Han), U+D55C (Hangul) and U+00E9 (Latin
     * letter with diacritic): no Windows ANSI code page can represent all of them at once,
     * so reading this value with the ANSI API always loses characters, either replaced by
     * '?' or best-fitted to a different character.
     */
    const std::wstring wideData {L"\u6DF1\u5733\u6C49\uD55C\u00E9"};
    const std::string expectedUtf8 {"\xE6\xB7\xB1\xE5\x9C\xB3\xE6\xB1\x89\xED\x95\x9C\xC3\xA9"};

    ASSERT_TRUE(writeWideTestValue(wideData));

    std::string utf8Value;
    std::string ansiValue;
    {
        Utils::Registry reg(HKEY_CURRENT_USER, UTF8_TEST_SUBKEY);
        EXPECT_TRUE(reg.stringUtf8(UTF8_TEST_VALUE, utf8Value));
        EXPECT_TRUE(reg.string(UTF8_TEST_VALUE, ansiValue));
    }

    RegDeleteKeyExW(HKEY_CURRENT_USER, UTF8_TEST_SUBKEY_W, KEY_WOW64_64KEY, 0);

    EXPECT_EQ(expectedUtf8, utf8Value);

    // Unless the system code page is UTF-8 itself, the ANSI path cannot return the same data.
    if (CP_UTF8 != GetACP())
    {
        EXPECT_NE(expectedUtf8, ansiValue);
    }
}

TEST_F(RegistryUtilsTest, RegistryStringUtf8NoThrow)
{
    std::string value;
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    EXPECT_FALSE(reg.stringUtf8("SomeWrongValue", value));
    EXPECT_TRUE(value.empty());
}

TEST_F(RegistryUtilsTest, RegistryStringUtf8RejectsNonStringValues)
{
    std::string value;
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);

    // "~MHz" is a REG_DWORD: it holds no text, so it must not be reported as a string.
    EXPECT_FALSE(reg.stringUtf8("~MHz", value));
    EXPECT_TRUE(value.empty());
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

#endif
