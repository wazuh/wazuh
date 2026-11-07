/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <optional>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "packages/appxWindowsWrapper.h"

/*
 * In-memory registry replacement for AppxWindowsWrapper tests.
 * Keys are stored as full paths and values as string/qword maps, so each test
 * describes the registry layout it needs. Like RegEnumKeyEx, enumeration
 * returns subkeys in alphabetical order.
 */
class FakeRegistry
{
    public:
        struct KeyData
        {
            std::map<std::string, std::string> strings;
            std::map<std::string, unsigned long long> qwords;
        };

        static std::map<std::string, KeyData> data;

        FakeRegistry(const HKEY, const std::string& subKey, const REGSAM = KEY_READ)
            : m_path{ subKey }
        {
            // Like the real registry, a key exists implicitly when any subkey exists under it.
            const auto prefix { subKey + "\\" };

            for (const auto& entry : data)
            {
                if (entry.first == subKey || Utils::startsWith(entry.first, prefix))
                {
                    return;
                }
            }

            throw std::runtime_error{ "Error opening registry: " + subKey };
        }

        std::vector<std::string> enumerate() const
        {
            std::vector<std::string> ret;
            const auto prefix { m_path + "\\" };

            for (const auto& entry : data)
            {
                if (Utils::startsWith(entry.first, prefix))
                {
                    const auto child { Utils::split(entry.first.substr(prefix.size()), '\\').front() };

                    if (std::find(ret.begin(), ret.end(), child) == ret.end())
                    {
                        ret.push_back(child);
                    }
                }
            }

            return ret;
        }

        std::vector<std::string> enumerateValueKey() const
        {
            std::vector<std::string> ret;
            const auto key { data.find(m_path) };

            if (key != data.end())
            {
                for (const auto& value : key->second.strings)
                {
                    ret.push_back(value.first);
                }
            }

            return ret;
        }

        /*
         * Mimics Registry::string(): the ANSI registry API hands the caller data already
         * transcoded to the system ANSI code page, so every character missing from that code
         * page is lost before the caller sees it. Replacing each non-ASCII byte reproduces
         * that loss, so a test using non-ASCII data fails if a call site goes back to the
         * ANSI path.
         */
        bool string(const std::string& valueName, std::string& value) const
        {
            if (!stringUtf8(valueName, value))
            {
                return false;
            }

            for (auto& character : value)
            {
                if (static_cast<unsigned char>(character) > 0x7F)
                {
                    character = '?';
                }
            }

            return true;
        }

        // Mimics Registry::stringUtf8(): the stored data is returned as UTF-8, untouched.
        bool stringUtf8(const std::string& valueName, std::string& value) const
        {
            const auto key { data.find(m_path) };

            if (key == data.end())
            {
                return false;
            }

            const auto it { key->second.strings.find(valueName) };

            if (it == key->second.strings.end())
            {
                return false;
            }

            value = it->second;
            return true;
        }

        bool qword(const std::string& valueName, unsigned long long& value) const
        {
            const auto key { data.find(m_path) };

            if (key == data.end())
            {
                return false;
            }

            const auto it { key->second.qwords.find(valueName) };

            if (it == key->second.qwords.end())
            {
                return false;
            }

            value = it->second;
            return true;
        }

    private:
        std::string m_path;
};

std::map<std::string, FakeRegistry::KeyData> FakeRegistry::data;

/*
 * In-memory replacement of AppxExeVersionReader: maps an executable path to the
 * product version that its VERSIONINFO resource would report.
 */
struct FakeExeVersionReader
{
    static std::map<std::string, std::string> versions;

    static std::string read(const std::string& exePath)
    {
        const auto it { versions.find(exePath) };
        return it == versions.end() ? "" : it->second;
    }
};

std::map<std::string, std::string> FakeExeVersionReader::versions;

/*
 * In-memory replacement of AppxDirectorySize: maps a package root folder to the size its walk
 * would establish, and counts the walks. A folder not in the map cannot be measured.
 */
struct FakeDirectorySize
{
    static std::map<std::string, std::uintmax_t> sizes;
    static int walks;

    static std::optional<std::uintmax_t> measure(const std::string& path)
    {
        ++walks;
        const auto it { sizes.find(path) };
        return it == sizes.end() ? std::nullopt : std::optional<std::uintmax_t> { it->second };
    }
};

std::map<std::string, std::uintmax_t> FakeDirectorySize::sizes;
int FakeDirectorySize::walks { 0 };

constexpr auto TEST_USER_SID { "S-1-5-21-1111111111-2222222222-3333333333-1001" };
constexpr auto TEST_STORE_REGISTRY { "SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages" };
constexpr auto TEST_CLASSES_REGISTRY { "SOFTWARE\\Classes" };
constexpr auto TEST_CACHE_REGISTRY { "SOFTWARE\\Classes\\Local Settings\\MrtCache" };

using TestAppxWrapper = TAppxWindowsWrapper<FakeRegistry, FakeExeVersionReader, FakeDirectorySize>;

class SysInfoWinAppxTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            FakeRegistry::data.clear();
            FakeExeVersionReader::versions.clear();
            FakeDirectorySize::sizes.clear();
            FakeDirectorySize::walks = 0;
        }

        std::string packagePath(const std::string& packageFullName) const
        {
            return std::string{ TEST_USER_SID } + "\\" + TEST_STORE_REGISTRY + "\\" + packageFullName;
        }

        /*
         * Registry layout of the Python 3.13 Microsoft Store package: one MSIX package
         * bundling three sub-applications (Pip, Python, PythonW). "Pip" is the first
         * subkey in alphabetical order but is NOT the primary application. The root key
         * has CapabilityCount 0; capabilities live only in the subkeys.
         */
        void loadPythonStorePackage(const std::string& packageFullName, const bool withDisplayName)
        {
            const auto root { packagePath(packageFullName) };

            FakeRegistry::data[root].strings["PackageRootFolder"] = "C:\\Program Files\\WindowsApps\\" + packageFullName;
            FakeRegistry::data[root].strings["PackageID"] = packageFullName;
            FakeRegistry::data[root].qwords["CapabilityCount"] = 0;

            if (withDisplayName)
            {
                FakeRegistry::data[root].strings["DisplayName"] = "Python 3.13";
            }

            FakeRegistry::data[root + "\\Pip\\Capabilities"].strings["ApplicationName"] = "pip (Python 3.13)";
            FakeRegistry::data[root + "\\Python\\Capabilities"].strings["ApplicationName"] = "Python 3.13";
            FakeRegistry::data[root + "\\PythonW\\Capabilities"].strings["ApplicationName"] = "Python 3.13 (Windowed)";

            FakeRegistry::data[root + "\\Pip\\Capabilities\\FileAssociations"].strings[".whl"] = "PythonSoftwareFoundation.whl";
            FakeRegistry::data[std::string{ TEST_USER_SID } + "\\" + TEST_CLASSES_REGISTRY + "\\PythonSoftwareFoundation.whl\\Application"]
            .strings["ApplicationCompany"] = "Python Software Foundation";
        }
};

constexpr auto PYTHON_PACKAGE { "PythonSoftwareFoundation.Python.3.13_3.13.3824.0_x64__qbz5n2kfra8p0" };

constexpr auto PYTHON_PACKAGE_ROOT { "C:\\Program Files\\WindowsApps\\PythonSoftwareFoundation.Python.3.13_3.13.3824.0_x64__qbz5n2kfra8p0" };

TEST_F(SysInfoWinAppxTest, SizeIsTheMeasuredPackageRootFolder)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);
    FakeDirectorySize::sizes[PYTHON_PACKAGE_ROOT] = 123456;

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ(wrapper.size(), 123456);
}

TEST_F(SysInfoWinAppxTest, SizeIsUnknownRatherThanZero)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    // The walk could not establish a size. Reporting 0 would be indistinguishable from a
    // package that genuinely occupies nothing, and would overwrite a previously known size.
    EXPECT_EQ(wrapper.size(), std::nullopt);
    EXPECT_NE(wrapper.size(), 0);
}

TEST_F(SysInfoWinAppxTest, EmptyPackageRootFolderSizeIsUnknown)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);
    FakeDirectorySize::sizes[PYTHON_PACKAGE_ROOT] = 0;

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ(wrapper.size(), std::nullopt);
}

TEST_F(SysInfoWinAppxTest, PackageSharedByUsersIsWalkedOnce)
{
    constexpr auto OTHER_USER_SID { "S-1-5-21-1111111111-2222222222-3333333333-1002" };
    loadPythonStorePackage(PYTHON_PACKAGE, true);
    const auto root { packagePath(PYTHON_PACKAGE) };
    const auto otherRoot { std::string{ OTHER_USER_SID } + "\\" + TEST_STORE_REGISTRY + "\\" + PYTHON_PACKAGE };
    FakeRegistry::data[otherRoot] = FakeRegistry::data[root];
    FakeRegistry::data[otherRoot + "\\Python\\Capabilities"] = FakeRegistry::data[root + "\\Python\\Capabilities"];
    FakeDirectorySize::sizes[PYTHON_PACKAGE_ROOT] = 123456;

    AppxSizeCache cache;
    TestAppxWrapper first(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {}, &cache);
    TestAppxWrapper second(HKEY_USERS, OTHER_USER_SID, PYTHON_PACKAGE, {}, &cache);

    EXPECT_EQ(first.size(), 123456);
    EXPECT_EQ(second.size(), 123456);
    EXPECT_EQ(FakeDirectorySize::walks, 1);
}

TEST_F(SysInfoWinAppxTest, MultiApplicationPackageUsesDisplayName)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ("Python 3.13", wrapper.name());
    EXPECT_EQ("3.13.3824.0", wrapper.version());
    EXPECT_EQ("x86_64", wrapper.architecture());
    EXPECT_EQ("Python Software Foundation", wrapper.vendor());
    EXPECT_EQ(std::string{ "C:\\Program Files\\WindowsApps\\" } + PYTHON_PACKAGE, wrapper.location());
    EXPECT_EQ("win", wrapper.format());
}

TEST_F(SysInfoWinAppxTest, FallbackToFirstApplicationNameWithoutDisplayName)
{
    loadPythonStorePackage(PYTHON_PACKAGE, false);

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    // Legacy behavior: without DisplayName the first sub-application found is reported.
    EXPECT_EQ("pip (Python 3.13)", wrapper.name());
}

TEST_F(SysInfoWinAppxTest, SingleApplicationPackageKeepsItsName)
{
    constexpr auto edgePackage { "Microsoft.MicrosoftEdge.Stable_120.0.2210.91_x64__8wekyb3d8bbwe" };
    const auto root { packagePath(edgePackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + edgePackage;
    FakeRegistry::data[root].strings["DisplayName"] = "Microsoft Edge";
    FakeRegistry::data[root + "\\Msedge\\Capabilities"].strings["ApplicationName"] = "Microsoft Edge";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, edgePackage, {});

    EXPECT_EQ("Microsoft Edge", wrapper.name());
    EXPECT_EQ("120.0.2210.91", wrapper.version());
}

TEST_F(SysInfoWinAppxTest, LocalizedDisplayNameResolvedFromCacheRegistry)
{
    constexpr auto calculatorPackage { "Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe" };
    constexpr auto resourceKey { "@{Microsoft.WindowsCalculator?ms-resource://AppName}" };
    const auto root { packagePath(calculatorPackage) };
    const auto cacheFolder { "Microsoft.WindowsCalculator_8wekyb3d8bbwe" };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + calculatorPackage;
    FakeRegistry::data[root].strings["DisplayName"] = resourceKey;
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = resourceKey;
    FakeRegistry::data[std::string{ TEST_USER_SID } + "\\" + TEST_CACHE_REGISTRY + "\\" + cacheFolder].strings[resourceKey] = "Calculator";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, calculatorPackage, { cacheFolder });

    EXPECT_EQ("Calculator", wrapper.name());
}

TEST_F(SysInfoWinAppxTest, UnresolvedLocalizedDisplayNameFallsBackToCapabilities)
{
    constexpr auto photosPackage { "Microsoft.Windows.Photos_2024.11010.0.0_x64__8wekyb3d8bbwe" };
    const auto root { packagePath(photosPackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + photosPackage;
    FakeRegistry::data[root].strings["DisplayName"] = "@{Microsoft.Windows.Photos?ms-resource://AppName}";
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = "Microsoft Photos";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, photosPackage, {});

    EXPECT_EQ("Microsoft Photos", wrapper.name());
}

TEST_F(SysInfoWinAppxTest, RawMsResourceDisplayNameFallsBackToCapabilities)
{
    constexpr auto calculatorPackage { "Microsoft.WindowsCalculator_11.2605.9.0_x64__8wekyb3d8bbwe" };
    const auto root { packagePath(calculatorPackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + calculatorPackage;
    // Real-world case: DisplayName holds an unresolved manifest resource URI.
    FakeRegistry::data[root].strings["DisplayName"] = "ms-resource:AppStoreName";
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = "Calculadora";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, calculatorPackage, {});

    EXPECT_EQ("Calculadora", wrapper.name());
}

TEST_F(SysInfoWinAppxTest, CacheRegistryErrorFallsBackToCapabilities)
{
    constexpr auto notesPackage { "Microsoft.MicrosoftStickyNotes_6.1.2.0_x64__8wekyb3d8bbwe" };
    const auto root { packagePath(notesPackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + notesPackage;
    FakeRegistry::data[root].strings["DisplayName"] = "@{Microsoft.MicrosoftStickyNotes?ms-resource://AppName}";
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = "Sticky Notes";

    // The cache folder matches the package but its MrtCache key is unreadable: the
    // resulting registry error must not prevent the ApplicationName fallback.
    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, notesPackage, { "Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe" });

    EXPECT_EQ("Sticky Notes", wrapper.name());
}

TEST_F(SysInfoWinAppxTest, PythonVersionEnrichedFromInterpreterExecutable)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);

    // Product version published by python.exe VERSIONINFO, as dumped from a real host
    // where the MSIX revision of the same package is 3.13.3824.0.
    FakeExeVersionReader::versions[std::string{ "C:\\Program Files\\WindowsApps\\" } + PYTHON_PACKAGE + "\\python.exe"] = "3.13.14";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ("Python 3.13", wrapper.name());
    EXPECT_EQ("3.13.14", wrapper.version());
}

TEST_F(SysInfoWinAppxTest, PythonWithoutReadableExecutableKeepsMsixVersion)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);

    // python.exe missing or without VERSIONINFO: keep the MSIX package revision.
    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ("3.13.3824.0", wrapper.version());
}

TEST_F(SysInfoWinAppxTest, PythonOnNetworkPathNeverOpensExecutable)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);

    const std::string networkRoot { std::string{ "\\\\10.0.0.5\\s\\C:\\Program Files\\WindowsApps\\" } + PYTHON_PACKAGE };
    FakeRegistry::data[packagePath(PYTHON_PACKAGE)].strings["PackageRootFolder"] = networkRoot;
    FakeExeVersionReader::versions[networkRoot + "\\python.exe"] = "9.9.9";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ("3.13.3824.0", wrapper.version());
}

TEST_F(SysInfoWinAppxTest, PackageOnNetworkPathIsNeverWalked)
{
    loadPythonStorePackage(PYTHON_PACKAGE, true);

    // Contains the WindowsApps text, so it passes the substring check, but it is a network share
    const std::string networkRoot { std::string{ "\\\\10.0.0.5\\s\\C:\\Program Files\\WindowsApps\\" } + PYTHON_PACKAGE };
    FakeRegistry::data[packagePath(PYTHON_PACKAGE)].strings["PackageRootFolder"] = networkRoot;
    FakeDirectorySize::sizes[networkRoot] = 123456;

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, PYTHON_PACKAGE, {});

    EXPECT_EQ(wrapper.size(), std::nullopt);
    EXPECT_EQ(FakeDirectorySize::walks, 0);
}

TEST_F(SysInfoWinAppxTest, NonPythonPackageNeverUsesExecutableVersion)
{
    constexpr auto edgePackage { "Microsoft.MicrosoftEdge.Stable_120.0.2210.91_x64__8wekyb3d8bbwe" };
    const auto root { packagePath(edgePackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + edgePackage;
    FakeRegistry::data[root].strings["DisplayName"] = "Microsoft Edge";
    FakeRegistry::data[root + "\\Msedge\\Capabilities"].strings["ApplicationName"] = "Microsoft Edge";

    // Even if an executable published a version, non-Python packages must keep the MSIX
    // version: bundled executables often publish bogus VERSIONINFO values.
    FakeExeVersionReader::versions[std::string{ "C:\\Program Files\\WindowsApps\\" } + edgePackage + "\\python.exe"] = "9.9.9";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, edgePackage, {});

    EXPECT_EQ("120.0.2210.91", wrapper.version());
}

TEST_F(SysInfoWinAppxTest, PackageOutsideStoreDatabaseIsDiscarded)
{
    constexpr auto strayPackage { "Vendor.StrayApp_1.0.0.0_x64__abcdef123456" };
    const auto root { packagePath(strayPackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = "C:\\SomeOtherFolder\\StrayApp";
    FakeRegistry::data[root].strings["DisplayName"] = "Stray App";
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = "Stray App";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, strayPackage, {});

    EXPECT_TRUE(wrapper.name().empty());
    EXPECT_TRUE(wrapper.version().empty());
    EXPECT_TRUE(wrapper.location().empty());
    // A package that is not reported is not worth walking
    EXPECT_EQ(FakeDirectorySize::walks, 0);
}

TEST_F(SysInfoWinAppxTest, MalformedPackageNameIsDiscarded)
{
    constexpr auto malformedPackage { "NotAStorePackageName" };
    const auto root { packagePath(malformedPackage) };

    FakeRegistry::data[root].strings["DisplayName"] = "Whatever";
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = "Whatever";

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, malformedPackage, {});

    EXPECT_TRUE(wrapper.name().empty());
    EXPECT_TRUE(wrapper.version().empty());
}

/*
 * Package names, sub-application names and publishers can hold characters that the system
 * ANSI code page cannot represent, so they must be read through the Unicode registry API.
 * FakeRegistry::string() drops non-ASCII characters exactly like the ANSI API does, so these
 * tests fail if any of those values is read through it again. The expected data is written as
 * hex escapes to keep this file ASCII.
 */
TEST_F(SysInfoWinAppxTest, NonAsciiDisplayNameAndPublisherAreReadAsUtf8)
{
    constexpr auto wechatPackage { "Tencent.WeChat_3.9.10.19_x64__a1b2c3d4e5f6" };
    // U+5FAE U+4FE1 ("WeChat" in Chinese), UTF-8 encoded.
    constexpr auto displayName { "\xE5\xBE\xAE\xE4\xBF\xA1" };
    // U+9A30 U+8A0A U+79D1 U+6280 ("Tencent Technology" in Chinese), UTF-8 encoded.
    constexpr auto publisher { "\xE9\xA8\xB0\xE8\xA8\x8A\xE7\xA7\x91\xE6\x8A\x80" };
    const auto root { packagePath(wechatPackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + wechatPackage;
    FakeRegistry::data[root].strings["DisplayName"] = displayName;
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = displayName;
    FakeRegistry::data[root + "\\App\\Capabilities\\FileAssociations"].strings[".wxwork"] = "Tencent.WeChat.wxwork";
    FakeRegistry::data[std::string{ TEST_USER_SID } + "\\" + TEST_CLASSES_REGISTRY + "\\Tencent.WeChat.wxwork\\Application"]
    .strings["ApplicationCompany"] = publisher;

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, wechatPackage, {});

    EXPECT_EQ(displayName, wrapper.name());
    EXPECT_EQ(publisher, wrapper.vendor());
}

TEST_F(SysInfoWinAppxTest, NonAsciiApplicationNameFallbackIsReadAsUtf8)
{
    constexpr auto notepadPackage { "Microsoft.WindowsNotepad_11.2402.22.0_x64__8wekyb3d8bbwe" };
    // U+8A18 U+4E8B U+672C ("Notepad" in Chinese), UTF-8 encoded.
    constexpr auto applicationName { "\xE8\xA8\x98\xE4\xBA\x8B\xE6\x9C\xAC" };
    const auto root { packagePath(notepadPackage) };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + notepadPackage;
    // No DisplayName: the name comes from the sub-application capabilities.
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = applicationName;

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, notepadPackage, {});

    EXPECT_EQ(applicationName, wrapper.name());
}

TEST_F(SysInfoWinAppxTest, NonAsciiLocalizedNameFromCacheRegistryIsReadAsUtf8)
{
    constexpr auto calculatorPackage { "Microsoft.WindowsCalculator_11.2401.0.0_x64__8wekyb3d8bbwe" };
    constexpr auto resourceKey { "@{Microsoft.WindowsCalculator?ms-resource://AppName}" };
    // U+8A08 U+7B97 U+6A5F ("Calculator" in Chinese), UTF-8 encoded.
    constexpr auto localizedName { "\xE8\xA8\x88\xE7\xAE\x97\xE6\xA9\x9F" };
    const auto root { packagePath(calculatorPackage) };
    const auto cacheFolder { "Microsoft.WindowsCalculator_8wekyb3d8bbwe" };

    FakeRegistry::data[root].strings["PackageRootFolder"] = std::string{ "C:\\Program Files\\WindowsApps\\" } + calculatorPackage;
    FakeRegistry::data[root].strings["DisplayName"] = resourceKey;
    FakeRegistry::data[root + "\\App\\Capabilities"].strings["ApplicationName"] = resourceKey;
    FakeRegistry::data[std::string{ TEST_USER_SID } + "\\" + TEST_CACHE_REGISTRY + "\\" + cacheFolder].strings[resourceKey] = localizedName;

    TestAppxWrapper wrapper(HKEY_USERS, TEST_USER_SID, calculatorPackage, { cacheFolder });

    EXPECT_EQ(localizedName, wrapper.name());
}
