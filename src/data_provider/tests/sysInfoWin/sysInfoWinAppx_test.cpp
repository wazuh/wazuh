/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * July 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
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

        bool string(const std::string& valueName, std::string& value) const
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

constexpr auto TEST_USER_SID { "S-1-5-21-1111111111-2222222222-3333333333-1001" };
constexpr auto TEST_STORE_REGISTRY { "SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages" };
constexpr auto TEST_CLASSES_REGISTRY { "SOFTWARE\\Classes" };
constexpr auto TEST_CACHE_REGISTRY { "SOFTWARE\\Classes\\Local Settings\\MrtCache" };

using TestAppxWrapper = TAppxWindowsWrapper<FakeRegistry, FakeExeVersionReader>;

class SysInfoWinAppxTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            FakeRegistry::data.clear();
            FakeExeVersionReader::versions.clear();
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
