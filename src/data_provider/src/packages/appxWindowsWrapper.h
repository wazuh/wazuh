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
            return UNKNOWN_VALUE;
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

        struct attributesAppName
        {
            std::string name;
            std::string version;
            std::string architecture;
            std::string uuid;
        };

        bool isRegistryValid()
        {
            Utils::Registry registry(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName, KEY_READ | KEY_ENUMERATE_SUB_KEYS);

            return registry.enumerate().size() != 0 ? true : false;
        }

        void getInformationPackages()
        {
            if (isRegistryValid())
            {
                constexpr auto INDEX_NAME { 0 };
                constexpr auto INDEX_VERSION { 1 };
                constexpr auto INDEX_ARCHITECTURE { 2 };
                constexpr auto INDEX_UUID {4};
                const auto fields { Utils::split(m_appName, '_') }; //The name format is <complete name>_<Version>_<Architecture>_<UUID>

                if (fields.size() >= 5)
                {
                    const struct attributesAppName attributes = {.name = fields.at(INDEX_NAME), .version = fields.at(INDEX_VERSION), .architecture = fields.at(INDEX_ARCHITECTURE), .uuid = fields.at(INDEX_UUID)};

                    const Utils::Registry packageReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName);

                    m_version = attributes.version;
                    m_architecture = getArchitecture(attributes.architecture);
                    m_location = getLocation(packageReg);
                    m_installTime = getInstallTime(attributes);
                    m_name = getName(attributes.name, packageReg);
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


        const std::string getInstallTime(const struct attributesAppName& attributes)
        {
            std::string installTime { UNKNOWN_VALUE };
            unsigned long long int value;

            // Name of main registry is: app_Name + _ + app_UUID
            const std::string mainRegistry {attributes.name + "_" + attributes.uuid};

            try
            {
                const Utils::Registry installTimeRegistry {Utils::Registry(m_key, m_userId + "\\" + APPLICATION_INSTALL_TIME_REGISTRY + "\\" + mainRegistry + "\\" + m_appName)};

                if (installTimeRegistry.longint("InstallTime", value))
                {

                    // Format of value is 18-digit LDAP/FILETIME timestamps.
                    // 18-digit LDAP/FILETIME timestamps -> Epoch/Unix time
                    // (value/10000000ULL) - 11644473600ULL
                    const time_t time {static_cast<long int>((value / 10000000ULL) - WINDOWS_UNIX_EPOCH_DIFF_SECONDS)};
                    char formatString[20] = {0};

                    std::strftime(formatString, sizeof(formatString), "%Y/%m/%d %H:%M:%S", std::localtime(&time));
                    installTime.assign(formatString);
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
            constexpr auto INVALID_NAME_APP { "@{" };

            try
            {
                for (const auto& folder : registry.enumerate())
                {
                    std::string value;
                    const Utils::Registry nameReg(m_key, m_userId  + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_appName + "\\" + folder + "\\Capabilities");

                    if (nameReg.string("ApplicationName", value))
                    {
                        name = value;
                    }
                }
            }
            catch (...)
            {
                name.clear();
            }

            const auto pos { name.find(INVALID_NAME_APP) };

            /*
             * If the name starts with "@{" string then we need to look for the name on the cache registry.
             * The name obtained is the key for the app name.
             */
            if (pos != std::string::npos && pos == 0)
            {
                try
                {
                    name = searchNameFromCacheRegistry(keyName, name);
                }
                catch (...)
                {
                    name.clear();
                }
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
            constexpr auto INVALID_NAME_APP { "@{" };
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

            const auto index { name.find(INVALID_NAME_APP) };
            return (index != std::string::npos && index == 0) ? "" : name;
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
                    const auto index { data.find("@{") };

                    if (index != 0)
                    {
                        publisher = data;
                        break;
                    }
                }
            }

            return publisher;
        }
};

