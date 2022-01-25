/* * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * January 23, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <algorithm>
#include <iostream>
#include <string>
#include <set>
#include "ipackageWrapper.h"
#include "registryHelper.h"
#include "stringHelper.h"
#include "sharedDefs.h"


constexpr auto  APPLICATION_STORE_REGISTRY {"SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\Repository\\Packages"};
constexpr auto APPLICATION_VENDOR_REGISTRY {"SOFTWARE\\Classes"};
constexpr auto FILE_ASSOCIATIONS_REGISTRY  { "\\Capabilities\\FileAssociations" };
constexpr auto URL_ASSOCIATIONS_REGISTRY   { "\\Capabilities\\URLAssociations" };
constexpr auto CACHE_NAME_REGISTRY         { "SOFTWARE\\Classes\\Local Settings\\MrtCache" };
constexpr auto STORE_APPLICATION_DATABASE  { "C:\\Program Files\\WindowsApps" };

class AppxWindowsWrapper final : public IPackageWrapper
{
    public:

        explicit AppxWindowsWrapper(const HKEY key, const std::string& userId, const std::string& nameApp, const std::set<std::string>& cacheRegistry)
            : m_key{ key },
              m_userId{ userId },
              m_nameApp{ nameApp },
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
            return UNKNOWN_VALUE;
        }

        std::string multiarch() const override
        {
            return UNKNOWN_VALUE;
        }

    private:
        HKEY m_key;
        std::string m_userId;
        std::string m_nameApp;
        std::string m_format;
        std::string m_name;
        std::string m_version;
        std::string m_vendor;
        std::string m_architecture;
        std::string m_location;
        std::set<std::string> m_cacheReg;

        bool isRegistryValid()
        {
            Utils::Registry registry(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_nameApp, KEY_READ | KEY_ENUMERATE_SUB_KEYS);

            return registry.enumerate().size() != 0 ? true : false;
        }

        void getInformationPackages()
        {
            if (isRegistryValid())
            {
                constexpr auto INDEX_NAME { 0 };
                constexpr auto INDEX_VERSION { 1 };
                constexpr auto INDEX_ARCHITECTURE { 2 };
                const auto fields { Utils::split(m_nameApp, '_') }; //The name format is <complete name>_<Version>_<Architecture>_<UUID>

                if (fields.size() >= 3)
                {
                    Utils::Registry packageReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_nameApp);
                    m_version = fields.at(INDEX_VERSION);
                    m_architecture = getArchitecture(fields.at(INDEX_ARCHITECTURE));
                    m_location = getLocation(packageReg);
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
         * Getting location where is the data and configuration application.
         *
         * @param[in] registry  Registry object pointing to where the data is.
         *
         * @return Return package location.
         */
        const std::string getLocation(Utils::Registry& registry)
        {
            std::string location;

            return registry.string("PackageRootFolder", location) ? location : UNKNOWN_VALUE;
        }

        /*
         * @brief Get application name.
         *
         * @param[in] fullName Full application name.
         * @param[in] registry Registry object pointing to where the data is located.
         *
         * @return Return name application.
         */
        const std::string getName(const std::string& fullName, Utils::Registry& registry)
        {
            std::string name;
            const auto fieldName{ Utils::split(fullName, '.').back() }; // Will only use the last vector element.
            constexpr auto INVALID_NAME_APP { "@{" };

            for (const auto& folder : registry.enumerate())
            {
                try
                {
                    std::string value;
                    Utils::Registry nameReg(m_key, m_userId  + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_nameApp + "\\" + folder + "\\Capabilities");

                    if (nameReg.string("ApplicationName", value))
                    {
                        name = value;
                    }
                }
                catch (...)
                {
                }
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
                    name = searchNameFromCacheRegistry(fieldName, name);
                }
                catch (...)
                {
                }
            }

            const auto index { name.find(INVALID_NAME_APP) };
            return (index != std::string::npos && index == 0) ? "" : name;
        }

        /*
         * @brief Get application vendor name.
         *
         * @param[in] registry Registry object that points to where the sub-registries with the names of the registry with the data are located.
         *
         * @return Returns the vendor name
         */
        const std::string getVendor(Utils::Registry& registry)
        {
            std::string vendor;

            for (const auto& folder : registry.enumerate())
            {
                try
                {
                    Utils::Registry fileReg(m_key, m_userId + "\\" + APPLICATION_STORE_REGISTRY + "\\" + m_nameApp + "\\" + folder + FILE_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                    vendor = searchPublisher(fileReg);

                    if (vendor.size() == 0)
                    {
                        Utils::Registry urlReg(m_key, m_userId + "\\"  + APPLICATION_STORE_REGISTRY + "\\" + m_nameApp + "\\" + folder + URL_ASSOCIATIONS_REGISTRY, KEY_READ | KEY_QUERY_VALUE);
                        vendor = searchPublisher(urlReg);
                    }
                }
                catch (...)
                {
                }
            }

            return vendor;
        }

        /*
         * @brief Search the name application in the cache registry.
         *
         * @param[in] nameApp Abbreviation of the name application to look for in the cache registry.
         * @param[in] nameKey Name key where is the name application
         *
         * @return Return the name application.
         */
        const std::string searchNameFromCacheRegistry(const std::string& nameApp, const std::string& nameKey)
        {
            std::string registry;
            std::string name;

            // Looking for the named folder same like name app
            for (const auto& folder : m_cacheReg)
            {
                if (folder.find(nameApp) != std::string::npos)
                {
                    registry = folder;
                    break;
                }
            }

            if (registry.size() != 0 )
            {
                name = searchKeyOnSubRegistries(m_userId + "\\" + CACHE_NAME_REGISTRY + "\\" + registry, nameKey);
            }

            return name;
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
            Utils::Registry registry(m_key, path);

            if (!registry.string(key, value))
            {
                for (const auto& folder : Utils::Registry(m_key, path).enumerate())
                {
                    std::string tempPath { path + "\\" + folder };
                    value = searchKeyOnSubRegistries(tempPath, key);

                    if (value.size())
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
        const std::string searchPublisher(Utils::Registry& registry)
        {
            std::string publisher;

            for (const auto& value : registry.enumerateValueKey())
            {
                std::string data;
                std::string vendorRegistry;

                registry.string(value, vendorRegistry);
                Utils::Registry pubRegistry(m_key, m_userId  + "\\" + APPLICATION_VENDOR_REGISTRY + "\\" + vendorRegistry + "\\Application");

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

