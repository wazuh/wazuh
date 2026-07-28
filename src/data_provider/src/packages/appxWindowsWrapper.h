/* * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * January 23, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <ctime>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <set>
#include <vector>
#include "ipackageWrapper.h"
#include "registryHelper.h"
#include "windowsHelper.h"
#include "packagesWindowsParserHelper.h"
#include "stringHelper.h"
#include "sharedDefs.h"

constexpr auto APPLICATION_STORE_REGISTRY        {"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"};
constexpr auto APPLICATION_INSTALL_TIME_REGISTRY {"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Families"};
constexpr auto APPLICATION_VENDOR_REGISTRY       {"SOFTWARE\\Classes"};
constexpr auto FILE_ASSOCIATIONS_REGISTRY        { "\\Capabilities\\FileAssociations" };
constexpr auto URL_ASSOCIATIONS_REGISTRY         { "\\Capabilities\\URLAssociations" };
constexpr auto CACHE_NAME_REGISTRY               { "SOFTWARE\\Classes\\Local Settings\\MrtCache" };
constexpr auto STORE_APPLICATION_DATABASE        { "C:\\Program Files\\WindowsApps" };
constexpr auto PYTHON_STORE_PACKAGE_PREFIX       { "PythonSoftwareFoundation.Python" };
constexpr auto PYTHON_EXECUTABLE                 { "\\python.exe" };
constexpr auto PREFIX_LOCALIZATION               { "@{" };
constexpr auto PREFIX_MSRESOURCE                 { "ms-resource:" };


/*
 * @brief Reads the product version published on the VERSIONINFO resource of an executable.
 *
 * The MSIX package revision does not encode the product version, and the PEP 514 style
 * registrations of Store applications live in the MSIX virtualized hive, which is not
 * reachable under HKEY_USERS, so the executable is the only source available to the agent.
 */
struct AppxExeVersionReader
{
    static std::string read(const std::string& exePath)
    {
        return PackageWindowsHelper::getProductVersion(exePath);
    }
};

template <typename TRegistry = Utils::Registry, typename TExeVersionReader = AppxExeVersionReader>
class TAppxWindowsWrapper final : public IPackageWrapper
{
    public:

        explicit TAppxWindowsWrapper(const HKEY key, const std::string& userId, const std::string& appName, const std::set<std::string>& cacheRegistry)
            : m_key{ key },
              m_userId{ userId },
              m_appName{ appName },
              m_format{ "win" },
              m_cacheReg{ cacheRegistry }
        {
            getInformationPackages();
        }

        ~TAppxWindowsWrapper() = default;

        std::string name() const override
        {
            return m_name;
        }

        std::string version() const override
        {
            return m_version;
        }

        std::string groups() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string description() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string architecture() const override
        {
            return m_architecture;
        }

        std::string format() const override
        {
            return m_format;
        }

        std::string osPatch() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string source() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string location() const override
        {
            return m_location;
        }

        std::string priority() const override
        {
            return UNKNOWN_VALUE;
        }

        int64_t size() const override
        {
            return 0;
        }

        std::string vendor() const override
        {
            return m_vendor;
        }

        std::string install_time() const override
        {
            return m_installTime;
        }

        std::string multiarch() const override
        {
            return std::string();
        }

    private:
        HKEY m_key;
        std::string m_userId;
        std::string m_appName;
        std::string m_format;
        std::string m_name;
        std::string m_version;
        std::string m_vendor;
        std::string m_architecture;
        std::string m_location;
        std::string m_installTime;
        std::set<std::string> m_cacheReg;

        bool isRegistryValid()
        {
            TRegistry registry(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName, KEY_READ | KEY_ENUMERATE_SUB_KEYS);

            return registry.enumerate().size() != 0;
        }

        void getInformationPackages()
        {
            if (isRegistryValid())
            {
                enum
                {
                    INDEX_NAME,
                    INDEX_VERSION,
                    INDEX_ARCHITECTURE,
                    INDEX_VOID,
                    INDEX_UUID,
                    INDEX_COUNT
                };
                const auto fields { Utils::split(m_appName, '_') }; //The name format is <complete name>_<Version>_<Architecture>_<UUID>

                if (fields.size() >= INDEX_COUNT)
                {
                    const TRegistry packageReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName);

                    m_version = fields.at(INDEX_VERSION);
                    m_architecture = getArchitecture(fields.at(INDEX_ARCHITECTURE));
                    m_location = getLocation(packageReg);
                    m_installTime = getInstallTime(fields.at(INDEX_NAME), fields.at(INDEX_UUID));
                    m_name = getName(fields.at(INDEX_NAME), packageReg);
                    m_vendor = getVendor(packageReg);

                }

                /*
                 * If the package location is not in application store database provided by Windows then it is thrown away.
                 * https://answers.microsoft.com/en-us/windows/forum/all/what-is-cprogram-fileswindows-apps-hidden-folder/783b5a18-c44d-46f7-b638-e98054b7c2a8
                 */
                if (m_location.find(STORE_APPLICATION_DATABASE) == std::string::npos)
                {
                    m_name.clear();
                    m_vendor.clear();
                    m_architecture.clear();
                    m_version.clear();
                    m_location.clear();
                }
                else if (Utils::startsWith(fields.at(INDEX_NAME), PYTHON_STORE_PACKAGE_PREFIX))
                {
                    /*
                     * The version taken from the package full name is the MSIX package revision,
                     * which for the Python Store packages does not match the product version
                     * (revision 3.13.3824.0 contains Python 3.13.14), so prefer the version that
                     * the interpreter publishes on its executable. This is scoped to the Python
                     * family on purpose: for other Store packages the MSIX revision IS the
                     * product version, and their bundled executables often publish bogus
                     * VERSIONINFO values (0.0.0.0, commit hashes, helper tool versions).
                     */
                    const auto productVersion { TExeVersionReader::read(m_location + PYTHON_EXECUTABLE) };

                    if (!productVersion.empty())
                    {
                        m_version = productVersion;
                    }
                }
            }
        }

        /*
         * @brief Gets packages architecture.
         *
         * @param[in] field Field where the architecture type is.
         *
         * Type are:
         *          - x64
         *          - x86
         *
         * @return Return app architecture.
         */
        const std::string getArchitecture(const std::string& field)
        {
            std::string architecture { UNKNOWN_VALUE };

            if (!field.compare("x64"))
            {
                architecture = "x86_64";
            }
            else if (!field.compare("x86"))
            {
                architecture = "i686";
            }

            return architecture;
        }

        /*
         * Get the path where the application was installed.
         *
         * @param[in] registry  Registry object pointing to where the data is.
         *
         * @return Return package location.
         */
        const std::string getLocation(const TRegistry& registry)
        {
            std::string location;

            return registry.string("PackageRootFolder", location) ? location : UNKNOWN_VALUE;
        }


        const std::string getInstallTime(const std::string& name, const std::string& uuid)
        {
            std::string installTime { UNKNOWN_VALUE };
            unsigned long long int value;

            // Name of main registry is: app_Name + _ + app_UUID
            const auto mainRegistry {name + "_" + uuid};

            try
            {
                const TRegistry installTimeRegistry {TRegistry(m_key, m_userId + "\\" + APPLICATION_INSTALL_TIME_REGISTRY + "\\" + mainRegistry + "\\" + m_appName)};

                if (installTimeRegistry.qword("InstallTime", value))
                {
                    installTime = Utils::buildTimestamp(value);
                }
            }
            catch (...)
            {
            }

            return installTime;
        }

        /*
         * @brief Get the package name from the DisplayName value of the package root key.
         *
         * @param[in] keyName Abbreviation of the package name, used to resolve localized names.
         * @param[in] registry Registry object pointing to the package root key.
         *
         * @return Return the package name or an empty string if DisplayName is missing or cannot be resolved.
         */
        const std::string getDisplayName(const std::string& keyName, const TRegistry& registry)
        {
            std::string name;

            try
            {
                if (!registry.string("DisplayName", name))
                {
                    name.clear();
                }

                /*
                 * If the name starts with "@{" string then we need to look for the name on the cache registry.
                 * The name obtained is the key for the app name.
                 */
                if (Utils::startsWith(name, PREFIX_LOCALIZATION))
                {
                    name = searchNameFromCacheRegistry(keyName, name);
                }
                /*
                 * A raw "ms-resource:" URI is an unresolved manifest resource, not a
                 * displayable name, and it cannot be looked up on the cache registry.
                 */
                else if (Utils::startsWith(name, PREFIX_MSRESOURCE))
                {
                    name.clear();
                }
            }
            catch (...)
            {
                // Errors resolving DisplayName must not prevent the ApplicationName fallback.
                name.clear();
            }

            return name;
        }

        /*
         * @brief Get application name.
         *
         * @param[in] fullName Full application name.
         * @param[in] registry Registry object pointing to where the data is located.
         *
         * @return Return name application.
         */
        const std::string getName(const std::string& fullName, const TRegistry& registry)
        {
            std::string name;

            /*
             * Example of  fullName
             *
             * Microsoft.Windows.Search
             * Microsoft.SkypeApp
             */
            const auto keyName { Utils::split(fullName, '.').back() }; // Will only use the last vector element.

            try
            {
                /*
                 * The DisplayName of the package root key is the package name set by the OS.
                 * A package can bundle several sub-applications (e.g. the Python Store package
                 * contains Pip, Python and PythonW), each one with its own ApplicationName, so
                 * picking the first enumerated sub-application would return an arbitrary name.
                 */
                name = getDisplayName(keyName, registry);

                if (name.empty())
                {
                    for (const auto& folder : registry.enumerate())
                    {
                        std::string value;
                        const TRegistry nameReg(m_key, m_userId  + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + "\\Capabilities");

                        if (nameReg.string("ApplicationName", value))
                        {
                            name = value;
                            break;
                        }
                    }

                    /*
                     * If the name starts with "@{" string then we need to look for the name on the cache registry.
                     * The name obtained is the key for the app name.
                     */
                    if (Utils::startsWith(name, PREFIX_LOCALIZATION))
                    {
                        name = searchNameFromCacheRegistry(keyName, name);
                    }
                }
            }
            catch (...)
            {
                name.clear();
            }

            return name;
        }

        /*
         * @brief Get application vendor name.
         *
         * @param[in] registry Registry object that points to where the sub-registries with the names of the registry with the data are located.
         *
         * @return Returns the vendor name
         */
        const std::string getVendor(const TRegistry& registry)
        {
            std::string vendor;

            try
            {
                for (const auto& folder : registry.enumerate())
                {
                    const TRegistry fileReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + FILE_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                    vendor = searchPublisher(fileReg);

                    if (vendor.empty())
                    {
                        const TRegistry urlReg(m_key, m_userId + "\\"  + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + URL_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                        vendor = searchPublisher(urlReg);
                    }

                    if (!vendor.empty())
                    {
                        break;
                    }
                }
            }
            catch (...)
            {
                vendor.clear();
            }

            return vendor;
        }

        /*
         * @brief Search the name application in the cache registry.
         *
         * @param[in] appName Abbreviation of the name application to look for in the cache registry.
         * @param[in] nameKey Name key where is the name application
         *
         * @return Return the name application.
         */
        const std::string searchNameFromCacheRegistry(const std::string& appName, const std::string& nameKey)
        {
            std::string registry;
            std::string name;
            auto findCacheName
            {
                [&appName](const std::string folder)
                {
                    return folder.find(appName) != std::string::npos;
                }
            };

            const auto folder = std::find_if(m_cacheReg.begin(), m_cacheReg.end(), findCacheName);
            // Search for the name of the folder containing the application name

            if (folder != m_cacheReg.end())
            {
                registry = *folder;
            }

            if (!registry.empty())
            {
                name = searchKeyOnSubRegistries(m_userId + "\\" + CACHE_NAME_REGISTRY + "\\" + registry, nameKey);
            }

            return Utils::startsWith(name, PREFIX_LOCALIZATION) ? "" : name;
        }

        /*
         * @brief Search the key on the registry and sub-registries.
         *
         * @param[in] path Start path where you want to search.
         * @param[in] key Name key to look for
         *
         * @return Return the value of the key.
         */
        const std::string searchKeyOnSubRegistries(const std::string& path, const std::string& key)
        {
            std::string value;
            const TRegistry registry(m_key, path);

            if (!registry.string(key, value))
            {
                for (const auto& folder : TRegistry(m_key, path).enumerate())
                {
                    const std::string tempPath { path + "\\" + folder };
                    value = searchKeyOnSubRegistries(tempPath, key);

                    if (!value.empty())
                    {
                        break;
                    }
                }
            }

            return value;
        }

        /*
         * @brief Search the publisher name in a registry.
         *
         * @param[in] registry Registry object used to obtain the information.
         *
         * @return Returns the publisher name found.
         */
        const std::string searchPublisher(const TRegistry& registry)
        {
            std::string publisher;

            for (const auto& value : registry.enumerateValueKey())
            {
                std::string data;
                std::string vendorRegistry;

                registry.string(value, vendorRegistry);
                const TRegistry pubRegistry(m_key, m_userId  + "\\" + APPLICATION_VENDOR_REGISTRY + "\\" + vendorRegistry + "\\Application");

                if (pubRegistry.string("ApplicationCompany", data))
                {
                    if (!Utils::startsWith(data, PREFIX_LOCALIZATION))
                    {
                        publisher = data;
                        break;
                    }
                }
            }

            return publisher;
        }
};

using AppxWindowsWrapper = TAppxWindowsWrapper<>;

