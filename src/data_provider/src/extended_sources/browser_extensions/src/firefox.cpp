#include "firefox.hpp"
#include <iostream>
#include <filesystem>
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

FirefoxAddons FirefoxAddonsProvider::getAddons()
{
    FirefoxAddons firefoxAddons;

    for (const auto& userHome : std::filesystem::directory_iterator(m_firefoxAddonsWrapper->getHomePath()))
    {
        if (!std::filesystem::is_directory(userHome))
        {
            continue;
        }

        std::string username = userHome.path().filename();

        for (const auto& path : kFirefoxPaths)
        {
            std::filesystem::path firefoxInstallationPath = userHome.path() / path;

            if (!std::filesystem::exists(firefoxInstallationPath))
            {
                continue;
            }

            for (const auto& entity : std::filesystem::directory_iterator(firefoxInstallationPath))
            {
                if (!std::filesystem::is_directory(entity))
                {
                    continue;
                }

                if (entity.path().filename() == "Crash Reports" || entity.path().filename() == "Pending Pings")
                {
                    continue;
                }

                std::filesystem::path extensionsFilePath = entity.path() / kFirefoxExtensionsFile;

                if (!std::filesystem::exists(extensionsFilePath))
                {
                    continue;
                }

                std::ifstream extensionsFile(extensionsFilePath);
                nlohmann::json extensionsJson = nlohmann::json::parse(extensionsFile);
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
                        firefoxAddon.visible = false; // TODO: Make sure false is the correct default value here
                    }
                    else
                    {
                        firefoxAddon.visible = addon.value()["visible"].get<bool>();
                    }

                    if (!addon.value().contains("active") || addon.value()["active"].is_null())
                    {
                        firefoxAddon.active = false; // TODO: Make sure false is the correct default value here
                    }
                    else
                    {
                        firefoxAddon.active = addon.value()["active"].get<bool>();
                    }

                    if (!addon.value().contains("applyBackgroundUpdates") || addon.value()["applyBackgroundUpdates"].is_null())
                    {
                        firefoxAddon.autoupdate = false; // TODO: Make sure false is the correct default value here
                    }
                    else
                    {
                        firefoxAddon.autoupdate = addon.value()["applyBackgroundUpdates"].get<int8_t>();
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