/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <map>
#include <set>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "packages/offlineRegistryWindows.h"
#include "packages/appxWindowsWrapper.h"

/*
 * In-memory replacement of the Offline Registry Library: one hive, with its keys addressed by
 * ORHKEY handles that point to them, and a count of the handles left open.
 */
class FakeOffregApi
{
    public:
        struct Value
        {
            DWORD type;
            std::vector<BYTE> data;
        };

        struct Key
        {
            std::map<std::wstring, Key> subKeys;
            std::map<std::wstring, Value> values;
            FILETIME lastWriteTime {};
        };

        static FakeOffregApi& instance()
        {
            static FakeOffregApi s_instance;
            return s_instance;
        }

        void reset()
        {
            root = Key {};
            openHiveResult = ERROR_SUCCESS;
            openHandles = 0;
            openedHandle = nullptr;
        }

        Key& key(const std::wstring& path)
        {
            auto current {&root};

            for (const auto& name : split(path))
            {
                current = &current->subKeys[name];
            }

            return *current;
        }

        void setString(const std::wstring& path, const std::wstring& name, const std::wstring& value)
        {
            const auto bytes {reinterpret_cast<const BYTE*>(value.c_str())};
            key(path).values[name] = Value {REG_SZ, std::vector<BYTE>(bytes, bytes + (value.size() + 1) * sizeof(wchar_t))};
        }

        template <typename T>
        void setNumber(const std::wstring& path, const std::wstring& name, const DWORD type, const T value)
        {
            const auto bytes {reinterpret_cast<const BYTE*>(&value)};
            key(path).values[name] = Value {type, std::vector<BYTE>(bytes, bytes + sizeof(T))};
        }

        DWORD openHive(const std::wstring&, ORHKEY* hive) const
        {
            if (openHiveResult != ERROR_SUCCESS)
            {
                return openHiveResult;
            }

            ++openHandles;
            *hive = const_cast<Key*>(&root);
            return ERROR_SUCCESS;
        }

        DWORD openHive(const HANDLE file, ORHKEY* hive) const
        {
            openedHandle = file;
            return openHive(std::wstring {}, hive);
        }

        DWORD closeHive(const ORHKEY) const
        {
            --openHandles;
            return ERROR_SUCCESS;
        }

        DWORD openKey(const ORHKEY key, const std::wstring& subKey, ORHKEY* result) const
        {
            auto current {static_cast<Key*>(key)};

            for (const auto& name : split(subKey))
            {
                const auto it {current->subKeys.find(name)};

                if (it == current->subKeys.end())
                {
                    return ERROR_FILE_NOT_FOUND;
                }

                current = &it->second;
            }

            ++openHandles;
            *result = current;
            return ERROR_SUCCESS;
        }

        DWORD closeKey(const ORHKEY) const
        {
            --openHandles;
            return ERROR_SUCCESS;
        }

        DWORD enumKey(const ORHKEY key, const DWORD index, PWSTR name, PDWORD nameSize) const
        {
            const auto& subKeys {static_cast<Key*>(key)->subKeys};

            if (index >= subKeys.size())
            {
                return ERROR_NO_MORE_ITEMS;
            }

            return copyName(std::next(subKeys.begin(), index)->first, name, nameSize);
        }

        DWORD enumValue(const ORHKEY key, const DWORD index, PWSTR name, PDWORD nameSize) const
        {
            const auto& values {static_cast<Key*>(key)->values};

            if (index >= values.size())
            {
                return ERROR_NO_MORE_ITEMS;
            }

            return copyName(std::next(values.begin(), index)->first, name, nameSize);
        }

        DWORD getValue(const ORHKEY key, const std::wstring& valueName, PDWORD type, PVOID data, PDWORD dataSize) const
        {
            const auto& values {static_cast<Key*>(key)->values};
            const auto it {values.find(valueName)};

            if (it == values.end())
            {
                return ERROR_FILE_NOT_FOUND;
            }

            if (type)
            {
                *type = it->second.type;
            }

            const auto size {static_cast<DWORD>(it->second.data.size())};

            if (data && *dataSize < size)
            {
                *dataSize = size;
                return ERROR_MORE_DATA;
            }

            if (data)
            {
                std::copy(it->second.data.begin(), it->second.data.end(), static_cast<BYTE*>(data));
            }

            *dataSize = size;
            return ERROR_SUCCESS;
        }

        DWORD lastWriteTime(const ORHKEY key, PFILETIME time) const
        {
            *time = static_cast<Key*>(key)->lastWriteTime;
            return ERROR_SUCCESS;
        }

        Key root;
        DWORD openHiveResult {ERROR_SUCCESS};
        mutable int openHandles {0};
        mutable HANDLE openedHandle {nullptr};

    private:
        static std::vector<std::wstring> split(const std::wstring& path)
        {
            std::vector<std::wstring> names;
            size_t start {0};

            while (start < path.size())
            {
                const auto end {path.find(L'\\', start)};
                names.push_back(path.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start));
                start = end == std::wstring::npos ? path.size() : end + 1;
            }

            return names;
        }

        static DWORD copyName(const std::wstring& source, PWSTR name, PDWORD nameSize)
        {
            if (source.size() + 1 > *nameSize)
            {
                return ERROR_MORE_DATA;
            }

            std::copy(source.begin(), source.end(), name);
            name[source.size()] = L'\0';
            *nameSize = static_cast<DWORD>(source.size());
            return ERROR_SUCCESS;
        }
};

using TestOfflineHive = TOfflineHive<FakeOffregApi>;
using TestOfflineRegistry = TOfflineRegistry<FakeOffregApi>;

constexpr auto UNINSTALL_KEY = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

class SysInfoWinOfflineRegistryTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            FakeOffregApi::instance().reset();
        }

        FakeOffregApi& api()
        {
            return FakeOffregApi::instance();
        }
};

TEST_F(SysInfoWinOfflineRegistryTest, EnumeratesSubKeysAndReadsStrings)
{
    api().setString(std::wstring(UNINSTALL_KEY) + L"\\OneDriveSetup.exe", L"DisplayName", L"Microsoft OneDrive");
    api().setString(std::wstring(UNINSTALL_KEY) + L"\\OneDriveSetup.exe", L"DisplayVersion", L"26.153.0809.0004");
    api().key(std::wstring(UNINSTALL_KEY) + L"\\Other");

    const TestOfflineHive hive {L"C:\\Users\\user\\NTUSER.DAT"};
    ASSERT_EQ(static_cast<DWORD>(ERROR_SUCCESS), hive.result());

    const TestOfflineRegistry uninstall {hive.key(), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"};
    EXPECT_EQ((std::vector<std::string> {"OneDriveSetup.exe", "Other"}), uninstall.enumerate());

    const TestOfflineRegistry package {hive.key(), "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\OneDriveSetup.exe"};
    std::string value;
    EXPECT_TRUE(package.string("DisplayName", value));
    EXPECT_EQ("Microsoft OneDrive", value);
    EXPECT_EQ((std::vector<std::string> {"DisplayName", "DisplayVersion"}), package.enumerateValueKey());
}

TEST_F(SysInfoWinOfflineRegistryTest, StringsGoThroughTheAnsiCodePageAsTheRegistryReader)
{
    // Utils::Registry reads values in the ANSI code page and converts them to UTF-8.
    const std::wstring name {L"Caf\u00e9 \u6771\u4eac"};
    api().setString(L"Key", L"DisplayName", name);

    const TestOfflineHive hive {L"hive"};
    const TestOfflineRegistry key {hive.key(), "Key"};
    const auto ansi {Utils::EncodingWindowsHelper::wstringToStringAnsi(name)};

    EXPECT_EQ(ansi, key.string("DisplayName"));

    std::string value;
    EXPECT_TRUE(key.string("DisplayName", value));
    EXPECT_EQ(Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(ansi), value);
}

TEST_F(SysInfoWinOfflineRegistryTest, MissingKeyOrValueFailsAsTheRegistryReader)
{
    api().key(L"Key");
    const TestOfflineHive hive {L"hive"};

    EXPECT_THROW(TestOfflineRegistry(hive.key(), "Missing"), std::system_error);

    const TestOfflineRegistry key {hive.key(), "Key"};
    std::string value;
    EXPECT_THROW(key.string("Missing"), std::system_error);
    EXPECT_FALSE(key.string("Missing", value));

    ULONGLONG qword {};
    EXPECT_THROW(key.qword("Missing", qword), std::system_error);
}

TEST_F(SysInfoWinOfflineRegistryTest, QwordOnlyReadsQwordValues)
{
    api().setNumber<ULONGLONG>(L"Key", L"InstallTime", REG_QWORD, 133000000000000000ULL);
    api().setNumber<DWORD>(L"Key", L"Flags", REG_DWORD, 7);

    const TestOfflineHive hive {L"hive"};
    const TestOfflineRegistry key {hive.key(), "Key"};
    ULONGLONG value {};

    EXPECT_TRUE(key.qword("InstallTime", value));
    EXPECT_EQ(133000000000000000ULL, value);
    EXPECT_FALSE(key.qword("Flags", value));

    DWORD flags {};
    EXPECT_TRUE(key.dword("Flags", flags));
    EXPECT_EQ(7u, flags);
}

TEST_F(SysInfoWinOfflineRegistryTest, KeyModificationDateComesFromTheLastWriteTime)
{
    auto& key {api().key(L"Key")};
    key.lastWriteTime.dwHighDateTime = 0x01DB1234;
    key.lastWriteTime.dwLowDateTime = 0x56789ABC;

    const TestOfflineHive hive {L"hive"};
    const TestOfflineRegistry registry {hive.key(), "Key"};

    EXPECT_EQ(Utils::buildTimestamp(0x01DB123456789ABCULL), registry.keyModificationDate());
}

TEST_F(SysInfoWinOfflineRegistryTest, KeyNameTooLongForTheRegistryReaderFailsEnumeration)
{
    // Utils::Registry enumerates with a 255 character buffer, terminator included.
    api().key(L"Key\\" + std::wstring(255, L'a'));

    const TestOfflineHive hive {L"hive"};
    const TestOfflineRegistry key {hive.key(), "Key"};

    EXPECT_THROW(key.enumerate(), std::system_error);
}

TEST_F(SysInfoWinOfflineRegistryTest, HandlesAreReleased)
{
    api().setString(L"Key\\Sub", L"Value", L"data");

    {
        const TestOfflineHive hive {L"hive"};
        const TestOfflineRegistry key {hive.key(), "Key"};

        for (const auto& name : key.enumerate())
        {
            const TestOfflineRegistry sub {hive.key(), "Key\\" + name};
            EXPECT_EQ("data", sub.string("Value"));
        }

        EXPECT_THROW(TestOfflineRegistry(hive.key(), "Missing"), std::system_error);
    }

    EXPECT_EQ(0, api().openHandles);
}

TEST_F(SysInfoWinOfflineRegistryTest, HiveThatCannotBeOpenedReportsTheError)
{
    // The profile service holds the file of a hive it has loaded.
    api().openHiveResult = ERROR_SHARING_VIOLATION;

    const TestOfflineHive hive {L"hive"};

    EXPECT_EQ(static_cast<DWORD>(ERROR_SHARING_VIOLATION), hive.result());
    EXPECT_EQ(nullptr, hive.key());
    EXPECT_EQ(0, api().openHandles);
}

TEST_F(SysInfoWinOfflineRegistryTest, HiveIsReadThroughTheHandleItIsGiven)
{
    // The agent checks the file on a handle and has the hive read through that same handle.
    api().setString(L"Key", L"Value", L"data");
    const auto file {reinterpret_cast<HANDLE>(0x1234)};

    {
        const TestOfflineHive hive {file};
        ASSERT_EQ(static_cast<DWORD>(ERROR_SUCCESS), hive.result());
        EXPECT_EQ(file, api().openedHandle);
        EXPECT_EQ("data", TestOfflineRegistry(hive.key(), "Key").string("Value"));
    }

    EXPECT_EQ(0, api().openHandles);
}

TEST_F(SysInfoWinOfflineRegistryTest, StorePackageReadFromAClassesHiveFile)
{
    constexpr auto calculatorPackage { "Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe" };
    const auto root { Utils::EncodingWindowsHelper::stringToWStringAnsi(std::string{ APPLICATION_STORE_REGISTRY } + "\\" + calculatorPackage) };

    api().setString(root, L"PackageRootFolder", L"C:\\Program Files\\WindowsApps\\Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe");
    api().setString(root, L"DisplayName", L"Calculator");
    api().setString(root + L"\\App\\Capabilities\\FileAssociations", L".calc", L"AppX.calculator");
    api().setString(L"AppX.calculator\\Application", L"ApplicationCompany", L"Microsoft Corporation");

    const TestOfflineHive hive {L"UsrClass.dat"};
    const TAppxWindowsWrapper<TestOfflineRegistry> wrapper(hive.key(), "", calculatorPackage, {});

    EXPECT_EQ("Calculator", wrapper.name());
    EXPECT_EQ("11.2401.0.0", wrapper.version());
    EXPECT_EQ("x86_64", wrapper.architecture());
    EXPECT_EQ("Microsoft Corporation", wrapper.vendor());
}

TEST(SysInfoWinOfflineUserProfilesTest, OnlyUserProfilesWithNoSessionAreRead)
{
    const std::set<std::string> loadedUsers {"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001_Classes", "S-1-5-18"};

    EXPECT_TRUE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-21-1-2-3-1002", loadedUsers));
    EXPECT_TRUE(OfflineUserProfiles::isOfflineUserProfile("S-1-12-1-1-2-3-4", loadedUsers));

    // With a session.
    EXPECT_FALSE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-21-1-2-3-1001", loadedUsers));
    // Backup entry of a profile that failed to load.
    EXPECT_FALSE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-21-1-2-3-1002.bak", loadedUsers));
    // Service, virtual and application pool accounts, which Windows loads without a logon.
    EXPECT_FALSE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-18", loadedUsers));
    EXPECT_FALSE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-20", loadedUsers));
    EXPECT_FALSE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-80-1-2-3-4-5", loadedUsers));
    EXPECT_FALSE(OfflineUserProfiles::isOfflineUserProfile("S-1-5-82-1-2-3-4-5", loadedUsers));
}
