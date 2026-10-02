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

using JsonFieldHelpers::getBoolField;
using JsonFieldHelpers::getObjectField;
using JsonFieldHelpers::getStringField;

FirefoxAddonsProvider::FirefoxAddonsProvider(std::shared_ptr<IBrowserExtensionsWrapper> firefoxAddonsWrapper) : m_firefoxAddonsWrapper(std::move(firefoxAddonsWrapper)) {}

FirefoxAddonsProvider::FirefoxAddonsProvider() : m_firefoxAddonsWrapper(std::make_shared<BrowserExtensionsWrapper>()) {}

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
    return Utils::existsRegular(Utils::joinPaths(profilePath, FIREFOX_ADDONS_FILE));
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

    for (const auto& userDir : Utils::enumerateDir(homePath))
    {
        // Ignore ".", ".." and hidden directories
        if (Utils::startsWith(userDir, "."))
        {
            continue;
        }

        const std::string userHome = Utils::joinPaths(homePath, userDir);

        if (!Utils::existsDir(userHome) || !isValidPath(userHome))
        {
            continue;
        }

        std::string username = Utils::getFilename(userHome);

        for (const auto& path : FIREFOX_PATHS)
        {
            const std::string firefoxInstallationPath = Utils::joinPaths(userHome, path);

            if (!Utils::existsDir(firefoxInstallationPath) || !isValidPath(firefoxInstallationPath))
            {
                continue;
            }

            for (const auto& entry : Utils::enumerateDir(firefoxInstallationPath))
            {
                const std::string entity = Utils::joinPaths(firefoxInstallationPath, entry);

                if (!Utils::existsDir(entity) || !isValidPath(entity))
                {
                    continue;
                }

                if (Utils::getFilename(entity) == "Crash Reports" || Utils::getFilename(entity) == "Pending Pings")
                {
                    continue;
                }

                if (!isValidFirefoxProfile(entity))
                {
                    // not a valid profile directory, skip.
                    continue;
                }

                std::string extensionsFilePath = Utils::joinPaths(entity, FIREFOX_ADDONS_FILE);

                if (!isValidPath(extensionsFilePath))
                {
                    continue;
                }

                std::ifstream extensionsFile(extensionsFilePath);

                if (!extensionsFile.is_open())
                {
                    // Skip this profile if file cannot be opened
                    continue;
                }

                nlohmann::json extensionsJson;

                try
                {
                    extensionsJson = nlohmann::json::parse(extensionsFile);
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
                    firefoxAddon.uid = m_firefoxAddonsWrapper->getUserId(username);

                    // If any of "softDisable", "appDisabled" or "userDisabled" are true, then the addon is disabled.
                    firefoxAddon.disabled = getBoolField(addonJson, "softDisable", false) ||
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
    FirefoxAddons firefoxAddons = getAddons();
    return toJson(firefoxAddons);
}
