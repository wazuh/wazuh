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
#include "stringHelper.h"
#include "sharedDefs.h"

constexpr auto APPLICATION_STORE_REGISTRY        {"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"};
constexpr auto APPLICATION_INSTALL_TIME_REGISTRY {"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Families"};
constexpr auto APPLICATION_VENDOR_REGISTRY       {"SOFTWARE\\Classes"};
constexpr auto FILE_ASSOCIATIONS_REGISTRY        { "\\Capabilities\\FileAssociations" };
constexpr auto URL_ASSOCIATIONS_REGISTRY         { "\\Capabilities\\URLAssociations" };
constexpr auto CACHE_NAME_REGISTRY               { "SOFTWARE\\Classes\\Local Settings\\MrtCache" };
constexpr auto STORE_APPLICATION_DATABASE        { "C:\\Program Files\\WindowsApps" };
constexpr auto PREFIX_LOCALIZATION               { "@{" };


class AppxWindowsWrapper final : public IPackageWrapper
{
    public:

        explicit AppxWindowsWrapper(const HKEY key, const std::string& userId, const std::string& appName, const std::set<std::string>& cacheRegistry)
            : m_key{ key },
              m_userId{ userId },
              m_appName{ appName },
              m_format{ "win" },
              m_cacheReg{ cacheRegistry }
        {
            getInformationPackages();
        }

        ~AppxWindowsWrapper() = default;

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

        int size() const override
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
            Utils::Registry registry(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName, KEY_READ | KEY_ENUMERATE_SUB_KEYS);

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
                    const Utils::Registry packageReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName);

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
        const std::string getLocation(const Utils::Registry& registry)
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
                const Utils::Registry installTimeRegistry {Utils::Registry(m_key, m_userId + "\\" + APPLICATION_INSTALL_TIME_REGISTRY + "\\" + mainRegistry + "\\" + m_appName)};

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
         * @brief Get application name.
         *
         * @param[in] fullName Full application name.
         * @param[in] registry Registry object pointing to where the data is located.
         *
         * @return Return name application.
         */
        const std::string getName(const std::string& fullName, const Utils::Registry& registry)
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
                for (const auto& folder : registry.enumerate())
                {
                    std::string value;
                    const Utils::Registry nameReg(m_key, m_userId  + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + "\\Capabilities");

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
        const std::string getVendor(const Utils::Registry& registry)
        {
            std::string vendor;

            try
            {
                for (const auto& folder : registry.enumerate())
                {
                    const Utils::Registry fileReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + FILE_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                    vendor = searchPublisher(fileReg);

                    if (vendor.empty())
                    {
                        const Utils::Registry urlReg(m_key, m_userId + "\\"  + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + URL_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
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
            const Utils::Registry registry(m_key, path);

            if (!registry.string(key, value))
            {
                for (const auto& folder : Utils::Registry(m_key, path).enumerate())
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
        const std::string searchPublisher(const Utils::Registry& registry)
        {
            std::string publisher;

            for (const auto& value : registry.enumerateValueKey())
            {
                std::string data;
                std::string vendorRegistry;

                registry.string(value, vendorRegistry);
                const Utils::Registry pubRegistry(m_key, m_userId  + "\\" + APPLICATION_VENDOR_REGISTRY + "\\" + vendorRegistry + "\\Application");

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

