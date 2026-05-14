/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "firefox.hpp"
#include <fstream>

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

    for (auto userHome : Utils::enumerateDir(homePath))
    {
        // Ignore ".", ".." and hidden directories
        if (Utils::startsWith(userHome, "."))
        {
            continue;
        }

        userHome = Utils::joinPaths(homePath, userHome);

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

            for (auto entity : Utils::enumerateDir(firefoxInstallationPath))
            {
                entity = Utils::joinPaths(firefoxInstallationPath, entity);

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
                    FirefoxAddon firefoxAddon;
                    firefoxAddon.uid = m_firefoxAddonsWrapper->getUserId(username);

                    if (
                        // If any of "softDisable", "appDisabled" or "userDisabled" are true, then the addon is disabled.
                        (addon.value().contains("softDisable") && !addon.value()["softDisable"].is_null() && addon.value()["softDisable"].get<bool>()) ||
                        (addon.value().contains("appDisabled") && !addon.value()["appDisabled"].is_null() && addon.value()["appDisabled"].get<bool>()) ||
                        (addon.value().contains("userDisabled") && !addon.value()["userDisabled"].is_null() && addon.value()["userDisabled"].get<bool>())
                    )
                    {
                        firefoxAddon.disabled = true;
                    }
                    else
                    {
                        firefoxAddon.disabled = false;
                    }

                    if (!addon.value().contains("defaultLocale") || addon.value()["defaultLocale"].is_null())
                    {
                        firefoxAddon.name = "";
                        firefoxAddon.creator = "";
                        firefoxAddon.description = "";
                    }
                    else
                    {
                        if (!addon.value()["defaultLocale"].contains("name") || addon.value()["defaultLocale"]["name"].is_null())
                        {
                            firefoxAddon.name = "";
                        }
                        else
                        {
                            firefoxAddon.name = addon.value()["defaultLocale"]["name"].get<std::string>();
                        }

                        if (!addon.value()["defaultLocale"].contains("creator") || addon.value()["defaultLocale"]["creator"].is_null())
                        {
                            firefoxAddon.creator = "";
                        }
                        else
                        {
                            firefoxAddon.creator = addon.value()["defaultLocale"]["creator"].get<std::string>();
                        }

                        if (!addon.value()["defaultLocale"].contains("description") || addon.value()["defaultLocale"]["description"].is_null())
                        {
                            firefoxAddon.description = "";
                        }
                        else
                        {
                            firefoxAddon.description = addon.value()["defaultLocale"]["description"].get<std::string>();
                        }
                    }

                    if (!addon.value().contains("id") || addon.value()["id"].is_null())
                    {
                        firefoxAddon.identifier = "";
                    }
                    else
                    {
                        firefoxAddon.identifier = addon.value()["id"].get<std::string>();
                    }

                    if (!addon.value().contains("type") || addon.value()["type"].is_null())
                    {
                        firefoxAddon.type = "";
                    }
                    else
                    {
                        firefoxAddon.type = addon.value()["type"].get<std::string>();
                    }

                    if (!addon.value().contains("version") || addon.value()["version"].is_null())
                    {
                        firefoxAddon.version = "";
                    }
                    else
                    {
                        firefoxAddon.version = addon.value()["version"].get<std::string>();
                    }

                    if (!addon.value().contains("sourceURI") || addon.value()["sourceURI"].is_null())
                    {
                        firefoxAddon.source_url = "";
                    }
                    else
                    {
                        firefoxAddon.source_url = addon.value()["sourceURI"].get<std::string>();
                    }

                    if (!addon.value().contains("visible") || addon.value()["visible"].is_null())
                    {
                        firefoxAddon.visible = false;
                    }
                    else
                    {
                        firefoxAddon.visible = addon.value()["visible"].get<bool>();
                    }

                    if (!addon.value().contains("active") || addon.value()["active"].is_null())
                    {
                        firefoxAddon.active = false;
                    }
                    else
                    {
                        firefoxAddon.active = addon.value()["active"].get<bool>();
                    }

                    if (!addon.value().contains("applyBackgroundUpdates") || addon.value()["applyBackgroundUpdates"].is_null())
                    {
                        firefoxAddon.autoupdate = false;
                    }
                    else
                    {
                        firefoxAddon.autoupdate = static_cast<bool>(addon.value()["applyBackgroundUpdates"].get<int8_t>());
                    }

                    if (!addon.value().contains("location") || addon.value()["location"].is_null())
                    {
                        firefoxAddon.location = "";
                    }
                    else
                    {
                        firefoxAddon.location = addon.value()["location"].get<std::string>();
                    }

                    if (!addon.value().contains("path") || addon.value()["path"].is_null())
                    {
                        firefoxAddon.path = "";
                    }
                    else
                    {
                        firefoxAddon.path = addon.value()["path"].get<std::string>();
                    }

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
