/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "firefox.hpp"
#include "json_field_helpers.hpp"
#include <fstream>
#include "safe_file_reader.hpp"
#include "stringHelper.h"

#include <filesystem_wrapper.hpp>

using JsonFieldHelpers::getBoolField;
using JsonFieldHelpers::getObjectField;
using JsonFieldHelpers::getStringField;

FirefoxAddonsProvider::FirefoxAddonsProvider(
    std::shared_ptr<IBrowserExtensionsWrapper> firefoxAddonsWrapper,
    std::unique_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_firefoxAddonsWrapper(std::move(firefoxAddonsWrapper))
    , m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper) : std::make_unique<file_system::FileSystemWrapper>()) {}

FirefoxAddonsProvider::FirefoxAddonsProvider() : m_firefoxAddonsWrapper(std::make_shared<BrowserExtensionsWrapper>())
    , m_fileSystemWrapper(std::make_unique<file_system::FileSystemWrapper>()) {}

nlohmann::json FirefoxAddonsProvider::toJson(const FirefoxAddons& addons)
{
    nlohmann::json results = nlohmann::json::array();

    for (auto& addon : addons)
    {
        nlohmann::json entry;
        entry["active"] = addon.active;
        entry["autoupdate"] = addon.autoupdate;
        entry["creator"] = addon.creator;
        entry["description"] = addon.description;
        entry["disabled"] = addon.disabled;
        entry["identifier"] = addon.identifier;
        entry["location"] = addon.location;
        entry["name"] = addon.name;
        entry["path"] = addon.path;
        entry["source_url"] = addon.source_url;
        entry["type"] = addon.type;
        entry["uid"] = addon.uid;
        entry["version"] = addon.version;
        entry["visible"] = addon.visible;

        results.push_back(std::move(entry));
    }

    return results;
}

bool FirefoxAddonsProvider::isValidFirefoxProfile(const std::string& profilePath)
{
    return m_fileSystemWrapper->is_regular_file(std::filesystem::path(profilePath) / FIREFOX_ADDONS_FILE);
}

bool FirefoxAddonsProvider::isValidPath(const std::string& path)
{
    if (path.empty() ||
            path.find("..") != std::string::npos ||
            path.find("//") != std::string::npos ||
            path.length() > MAX_PATH_LENGTH)
    {
        return false;
    }

    return true;
}

FirefoxAddons FirefoxAddonsProvider::getAddons()
{
    FirefoxAddons firefoxAddons;
    const std::string homePath = m_firefoxAddonsWrapper->getHomePath();

    if (!isValidPath(homePath))
    {
        return firefoxAddons;
    }

    for (auto userHome : m_fileSystemWrapper->list_directory(homePath))
    {
        // Ignore ".", ".." and hidden directories
        if (Utils::startsWith(userHome.filename().string(), "."))
        {
            continue;
        }

        userHome = std::filesystem::path(homePath) / userHome;

        if (!m_fileSystemWrapper->is_directory(userHome) || !isValidPath(userHome.string()))
        {
            continue;
        }

        std::string username = userHome.filename().string();
        const std::string userId = m_firefoxAddonsWrapper->getUserId(username);
        const std::string ownerUid = userId.empty() ? browser_extensions::homeDirectoryOwner(userHome.string()) : userId;

        for (const auto& path : FIREFOX_PATHS)
        {
            const std::filesystem::path firefoxInstallationPath = userHome / path;

            if (!m_fileSystemWrapper->is_directory(firefoxInstallationPath) || !isValidPath(firefoxInstallationPath.string()))
            {
                continue;
            }

            for (auto entity : m_fileSystemWrapper->list_directory(firefoxInstallationPath))
            {
                entity = firefoxInstallationPath / entity;

                if (!m_fileSystemWrapper->is_directory(entity) || !browser_extensions::isPlainDirectory(entity.string()) ||
                        !isValidPath(entity.string()))
                {
                    continue;
                }

                if (entity.filename().string() == "Crash Reports" || entity.filename().string() == "Pending Pings")
                {
                    continue;
                }

                if (!isValidFirefoxProfile(entity.string()))
                {
                    // not a valid profile directory, skip.
                    continue;
                }

                std::filesystem::path extensionsFilePath = entity / FIREFOX_ADDONS_FILE;

                if (!isValidPath(extensionsFilePath.string()))
                {
                    continue;
                }

                std::string extensionsContent;

                if (!browser_extensions::readRegularFile(extensionsFilePath.string(), extensionsContent, ownerUid))
                {
                    // Skip this profile if the file cannot be read or is not a regular file
                    continue;
                }

                nlohmann::json extensionsJson;

                try
                {
                    extensionsJson = nlohmann::json::parse(extensionsContent);
                }
                catch (const nlohmann::json::parse_error& e)
                {
                    // Skip this profile if JSON is malformed
                    continue;
                }
                catch (const std::exception& e)
                {
                    // Skip this profile for any other parsing error
                    continue;
                }

                if (!extensionsJson.contains("addons") || !extensionsJson["addons"].is_array())
                {
                    // Skip this profile if addons key doesn't exist or isn't an array
                    continue;
                }

                const nlohmann::json& addons = extensionsJson["addons"];

                for (const auto& addon : addons.items())
                {
                    const nlohmann::json& addonJson = addon.value();
                    const nlohmann::json& defaultLocale = getObjectField(addonJson, "defaultLocale");

                    FirefoxAddon firefoxAddon;
                    firefoxAddon.uid = userId;

                    // If any of "softDisabled", "appDisabled" or "userDisabled" are true, then the addon is disabled.
                    firefoxAddon.disabled = getBoolField(addonJson, "softDisabled", false) ||
                                            getBoolField(addonJson, "appDisabled", false) ||
                                            getBoolField(addonJson, "userDisabled", false);

                    firefoxAddon.name = getStringField(defaultLocale, "name");
                    firefoxAddon.creator = getStringField(defaultLocale, "creator");
                    firefoxAddon.description = getStringField(defaultLocale, "description");
                    firefoxAddon.identifier = getStringField(addonJson, "id");
                    firefoxAddon.type = getStringField(addonJson, "type");
                    firefoxAddon.version = getStringField(addonJson, "version");
                    firefoxAddon.source_url = getStringField(addonJson, "sourceURI");
                    firefoxAddon.visible = getBoolField(addonJson, "visible", false);
                    firefoxAddon.active = getBoolField(addonJson, "active", false);

                    const auto autoupdateIt = addonJson.find("applyBackgroundUpdates");
                    firefoxAddon.autoupdate = autoupdateIt != addonJson.end() &&
                                              (autoupdateIt->is_number_integer() || autoupdateIt->is_boolean()) &&
                                              static_cast<bool>(autoupdateIt->get<int8_t>());

                    firefoxAddon.location = getStringField(addonJson, "location");
                    firefoxAddon.path = getStringField(addonJson, "path");

                    firefoxAddons.emplace_back(firefoxAddon);
                }
            }
        }
    }

    return firefoxAddons;
}

nlohmann::json FirefoxAddonsProvider::collect()
{
    try
    {
        FirefoxAddons firefoxAddons = getAddons();
        return toJson(firefoxAddons);
    }
    catch (const std::filesystem::filesystem_error&)
    {
        return nlohmann::json::array();
    }
}
