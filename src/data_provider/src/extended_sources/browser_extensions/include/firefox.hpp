#pragma once

#include <vector>
#include <map>
#include <string>
#include "json.hpp"
#include "browser_extensions_wrapper.hpp"

/// Each home directory will include custom extensions.
#if defined(__APPLE__)
const std::vector<std::string> kFirefoxPaths =
{
    "Library/Application Support/Firefox/Profiles/"
};
#elif defined(__linux__)
const std::vector<std::string> kFirefoxPaths =
{
    ".mozilla/firefox/", "snap/firefox/common/.mozilla/firefox/"
};
#elif defined(WIN32)
const std::vector<std::string> kFirefoxPaths =
{
    "AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
};
#endif

#define kFirefoxExtensionsFile "extensions.json"

/// Not parsed, but may be helpful later.
#define kFirefoxAddonsFile "/addons.json"
#define kFirefoxWebappsFile "/webapps/webapps.json"

const std::map<std::string, std::string> kFirefoxAddonKeys =
{
    {"defaultLocale.name", "name"},
    {"id", "identifier"},
    {"type", "type"},
    {"version", "version"},
    {"defaultLocale.creator", "creator"},
    {"defaultLocale.description", "description"},
    {"sourceURI", "source_url"},
    {"visible", "visible"},
    {"active", "active"},
    {"applyBackgroundUpdates", "autoupdate"},
    {"location", "location"},
    {"path", "path"},
};

struct FirefoxAddon
{
    bool active;
    bool autoupdate;
    std::string creator;
    std::string description;
    bool disabled;
    std::string identifier;
    std::string location;
    std::string name;
    std::string path;
    std::string source_url;
    std::string type;
    std::string uid;
    std::string version;
    bool visible;
};

using FirefoxAddons = std::vector<FirefoxAddon>;

class FirefoxAddonsProvider
{
    public:
        explicit FirefoxAddonsProvider(
            std::shared_ptr<IBrowserExtensionsWrapper> firefoxAddonsWrapper);
        FirefoxAddonsProvider();
        ~FirefoxAddonsProvider() = default;
        nlohmann::json collect();
    private:
        FirefoxAddons getAddons();
        nlohmann::json toJson(const FirefoxAddons& addons);
        std::shared_ptr<IBrowserExtensionsWrapper> m_firefoxAddonsWrapper;
};
