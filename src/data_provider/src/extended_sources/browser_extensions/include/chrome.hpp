/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>
#include <vector>
#include "json.hpp"
#include "chrome_extensions_wrapper.hpp"

namespace chrome
{

    struct ChromeExtension
    {
        std::string browser_type;
        std::string uid;
        std::string name;
        std::string profile;
        std::string profile_path;
        std::string referenced_identifier;
        std::string identifier;
        std::string version;
        std::string description;
        std::string default_locale;
        std::string current_locale;
        std::string update_url;
        std::string author;
        std::string persistent;
        std::string path;
        std::string permissions;
        std::string permissions_json;
        std::string optional_permissions;
        std::string optional_permissions_json;
        std::string manifest_hash;
        std::string referenced;
        std::string from_webstore;
        std::string state;
        std::string install_time;
        std::string install_timestamp;
        std::string manifest_json;
        std::string key;
    };

    /// One of the possible Chrome-based browser names
    enum class ChromeBrowserType
    {
        GoogleChrome,
        GoogleChromeBeta,
        GoogleChromeDev,
        GoogleChromeCanary,
        Brave,
        Chromium,
        Yandex,
        Opera,
        Edge,
        EdgeBeta,
        Vivaldi,
        Arc,
    };

    /// A list of possible path suffixes for each browser type
    using ChromePathSuffixMap = std::vector<std::tuple<ChromeBrowserType, std::string>>;
    using ChromeExtensionList = std::vector<ChromeExtension>;
    using ChromeUserProfileList = std::vector<std::string>;

    const ChromePathSuffixMap kLinuxPathList =
    {
        {ChromeBrowserType::GoogleChrome, ".config/google-chrome"},
        {ChromeBrowserType::GoogleChromeBeta, ".config/google-chrome-beta"},
        {ChromeBrowserType::GoogleChromeDev, ".config/google-chrome-unstable"},
        {ChromeBrowserType::Brave, ".config/BraveSoftware/Brave-Browser"},
        {ChromeBrowserType::Chromium, ".config/chromium"},
        {ChromeBrowserType::Chromium, "snap/chromium/common/chromium"},
        {ChromeBrowserType::Yandex, ".config/yandex-browser-beta"},
        {ChromeBrowserType::Opera, ".config/opera"},
        {ChromeBrowserType::Vivaldi, ".config/vivaldi"},
    };

    const ChromePathSuffixMap kMacOsPathList =
    {
        {ChromeBrowserType::GoogleChrome, "Library/Application Support/Google/Chrome"},
        {ChromeBrowserType::GoogleChromeBeta, "Library/Application Support/Google/Chrome Beta"},
        {ChromeBrowserType::GoogleChromeDev, "Library/Application Support/Google/Chrome Dev"},
        {ChromeBrowserType::GoogleChromeCanary, "Library/Application Support/Google/Chrome Canary"},
        {ChromeBrowserType::Brave, "Library/Application Support/BraveSoftware/Brave-Browser"},
        {ChromeBrowserType::Chromium, "Library/Application Support/Chromium"},
        {ChromeBrowserType::Yandex, "Library/Application Support/Yandex/YandexBrowser"},
        {ChromeBrowserType::Edge, "Library/Application Support/Microsoft Edge"},
        {ChromeBrowserType::EdgeBeta, "Library/Application Support/Microsoft Edge Beta"},
        {ChromeBrowserType::Opera, "Library/Application Support/com.operasoftware.Opera"},
        {ChromeBrowserType::Vivaldi, "Library/Application Support/Vivaldi"},
        {ChromeBrowserType::Arc, "Library/Application Support/Arc/User Data"}
    };

    const ChromePathSuffixMap kWindowsPathList =
    {
        {ChromeBrowserType::GoogleChrome, "AppData\\Local\\Google\\Chrome\\User Data"},
        {ChromeBrowserType::GoogleChromeBeta, "AppData\\Local\\Google\\Chrome Beta\\User Data"},
        {ChromeBrowserType::GoogleChromeDev, "AppData\\Local\\Google\\Chrome Dev\\User Data"},
        {ChromeBrowserType::GoogleChromeCanary, "AppData\\Local\\Google\\Chrome SxS\\User Data"},
        {ChromeBrowserType::Brave, "AppData\\Roaming\\brave"},
        {ChromeBrowserType::Chromium, "AppData\\Local\\Chromium"},
        {ChromeBrowserType::Yandex, "AppData\\Local\\Yandex\\YandexBrowser\\User Data"},
        {ChromeBrowserType::Edge, "AppData\\Local\\Microsoft\\Edge\\User Data"},
        {ChromeBrowserType::EdgeBeta, "AppData\\Local\\Microsoft\\Edge Beta\\User Data"},
        {ChromeBrowserType::Opera, "AppData\\Roaming\\Opera Software\\Opera Stable"},
        {ChromeBrowserType::Vivaldi, "AppData\\Local\\Vivaldi\\User Data"}
    };

    const std::unordered_map<ChromeBrowserType, std::string>
    kChromeBrowserTypeToString =
    {
        {ChromeBrowserType::GoogleChrome, "chrome"},
        {ChromeBrowserType::GoogleChromeBeta, "chrome_beta"},
        {ChromeBrowserType::GoogleChromeDev, "chrome_dev"},
        {ChromeBrowserType::GoogleChromeCanary, "chrome_canary"},
        {ChromeBrowserType::Brave, "brave"},
        {ChromeBrowserType::Chromium, "chromium"},
        {ChromeBrowserType::Yandex, "yandex"},
        {ChromeBrowserType::Opera, "opera"},
        {ChromeBrowserType::Edge, "edge"},
        {ChromeBrowserType::EdgeBeta, "edge_beta"},
        {ChromeBrowserType::Vivaldi, "vivaldi"},
        {ChromeBrowserType::Arc, "arc"},
    };

    const std::string kPreferencesFile{"Preferences"};
    const std::string kSecurePreferencesFile{"Secure Preferences"};
    const std::string kExtensionsDir{"Extensions"};
    const std::string kExtensionManifestFile{"manifest.json"};
    const std::string kExtensionLocalesDir{"_locales"};
    const std::string kExtensionLocaleMessagesFile{"messages.json"};

    class ChromeExtensionsProvider
    {
        public:
            explicit ChromeExtensionsProvider(
                std::shared_ptr<IChromeExtensionsWrapper> chromeExtensionsWrapper);
            ChromeExtensionsProvider();
            void printExtensions(const chrome::ChromeExtensionList& extensions);
            nlohmann::json collect();

        private:
            void getExtensionsFromProfiles(chrome::ChromeExtensionList& extensions);
            nlohmann::json toJson(const chrome::ChromeExtensionList& extensions);
            bool isValidChromeProfile(const std::string& profilePath);
            std::string jsonArrayToString(const nlohmann::json& jsonArray);
            std::string base64Decode(const std::string& input);
            bool isSnakeCase(const std::string& s);
            void localizeParameters(chrome::ChromeExtension& extension);
            std::string hashToLetterString(const uint8_t* hash, size_t length);
            std::string hashToHexString(const uint8_t* hash, size_t length);
            std::string webkitToUnixTime(std::string webkit_timestamp);
            std::string generateIdentifier(const std::string& key);
            std::string sha256File(const std::string& filepath);
            std::string getProfileFromPreferences(const std::string& preferencesFilePath, const std::string& securePreferencesFilePath);
            void parseManifest(nlohmann::json& manifestJson, chrome::ChromeExtension& extension);
            void parsePreferenceSettings(chrome::ChromeExtension& extension, const std::string& key, const nlohmann::json& value);
            void getCommonSettings(chrome::ChromeExtension& extension, const std::string& manifestPath);
            chrome::ChromeExtensionList getExtensionsFromPreferences(const std::string& profilePath, const std::string& preferencesFilePath, const std::string& profileName);
            chrome::ChromeExtensionList getReferencedExtensions(const std::string& profilePath);
            chrome::ChromeExtensionList getUnreferencedExtensions(const std::string& profilePath);
            void getExtensionsFromPath(chrome::ChromeExtensionList& extensions, const std::string& path);

            std::shared_ptr<IChromeExtensionsWrapper> m_chromeExtensionsWrapper;
            std::string m_currentBrowserType;
            std::string m_currentUid;
    };

} // namespace chrome
