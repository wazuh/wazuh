/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <vector>
#include <map>
#include <string>
#include "json.hpp"
#include "filesystemHelper.h"
#include "browser_extensions_wrapper.hpp"

/// Each home directory will include custom extensions.
#if defined(__APPLE__)
const std::vector<std::string> FIREFOX_PATHS =
{
    "Library/Application Support/Firefox/Profiles/"
};
#elif defined(__linux__)
const std::vector<std::string> FIREFOX_PATHS =
{
    ".mozilla/firefox/", "snap/firefox/common/.mozilla/firefox/"
};
#elif defined(WIN32)
const std::vector<std::string> FIREFOX_PATHS =
{
    "AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
};
#endif

#define FIREFOX_ADDONS_FILE "extensions.json"
#define MAX_PATH_LENGTH 4096

const std::map<std::string, std::string> FIREFOX_ADDON_KEYS =
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

/**
 * @class FirefoxAddonsProvider
 * @brief Provides functionality to collect and process Firefox browser addon information from user profiles.
 *
 * This class uses a browser extensions wrapper to access Firefox profile directories and extract addon metadata.
 * It offers methods to validate profiles, retrieve addon lists, and convert addon data to JSON format for further processing or reporting.
 */
class FirefoxAddonsProvider
{
    public:
        /**
         * @brief Construct a FirefoxAddonsProvider with a custom browser extensions wrapper.
         * @param firefoxAddonsWrapper Shared pointer to a browser extensions wrapper implementation.
         */
        explicit FirefoxAddonsProvider(
            std::shared_ptr<IBrowserExtensionsWrapper> firefoxAddonsWrapper);

        /**
         * @brief Default constructor for FirefoxAddonsProvider.
         */
        FirefoxAddonsProvider();

        /**
         * @brief Collects Firefox addon information and returns it as a JSON object.
         * @return nlohmann::json containing the collected addon data.
         */
        ~FirefoxAddonsProvider() = default;

        /**
         * @brief Collects Firefox addon information and returns it as a JSON object.
         * @return nlohmann::json containing the collected addon data.
         */
        nlohmann::json collect();
    private:
        /**
         * @brief Checks if the given path is a valid Firefox profile directory.
         * @param profilePath Path to the Firefox profile.
         * @return true if valid, false otherwise.
         */
        bool isValidFirefoxProfile(const std::string& profilePath);

        /**
         * @brief Validates path security to prevent directory traversal attacks.
         * @param path Path to validate.
         * @return true if path is safe, false otherwise.
         */
        bool isValidPath(const std::string& path);

        /**
         * @brief Retrieves the list of Firefox addons from available profiles.
         * @return FirefoxAddons vector containing addon information.
         */
        FirefoxAddons getAddons();

        /**
         * @brief Converts a list of Firefox addons to a JSON object.
         * @param addons Vector of FirefoxAddon objects.
         * @return nlohmann::json representation of the addons.
         */
        nlohmann::json toJson(const FirefoxAddons& addons);

        /**
         * @brief Pointer to the browser extensions wrapper implementation.
         */
        std::shared_ptr<IBrowserExtensionsWrapper> m_firefoxAddonsWrapper;
};
