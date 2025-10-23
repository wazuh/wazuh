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
#include "browser_extensions_wrapper.hpp"

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
        Comet
    };

    /// A list of possible path suffixes for each browser type
    using ChromePathSuffixMap = std::vector<std::tuple<ChromeBrowserType, std::string>>;
    using ChromeExtensionList = std::vector<ChromeExtension>;
    using ChromeUserProfileList = std::vector<std::string>;

    const ChromePathSuffixMap LINUX_PATH_LIST =
    {
        {ChromeBrowserType::GoogleChrome, ".config/google-chrome"},
        {ChromeBrowserType::GoogleChromeBeta, ".config/google-chrome-beta"},
        {ChromeBrowserType::GoogleChromeDev, ".config/google-chrome-unstable"},
        {ChromeBrowserType::Brave, ".config/BraveSoftware/Brave-Browser"},
        {ChromeBrowserType::Chromium, ".config/chromium"},
        {ChromeBrowserType::Chromium, "snap/chromium/common/chromium"},
        {ChromeBrowserType::Yandex, ".config/yandex-browser"},
        {ChromeBrowserType::Opera, ".config/opera"},
        {ChromeBrowserType::Vivaldi, ".config/vivaldi"},
    };

    const ChromePathSuffixMap MACOS_PATH_LIST =
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
        {ChromeBrowserType::Arc, "Library/Application Support/Arc/User Data"},
        {ChromeBrowserType::Comet, "Library/Application Support/Comet"}
    };

    const ChromePathSuffixMap WINDOWS_PATH_LIST =
    {
        {ChromeBrowserType::GoogleChrome, "AppData\\Local\\Google\\Chrome\\User Data"},
        {ChromeBrowserType::GoogleChromeBeta, "AppData\\Local\\Google\\Chrome Beta\\User Data"},
        {ChromeBrowserType::GoogleChromeDev, "AppData\\Local\\Google\\Chrome Dev\\User Data"},
        {ChromeBrowserType::GoogleChromeCanary, "AppData\\Local\\Google\\Chrome SxS\\User Data"},
        {ChromeBrowserType::Brave, "AppData\\Roaming\\brave"},
        {ChromeBrowserType::Brave, "AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data"},
        {ChromeBrowserType::Chromium, "AppData\\Local\\Chromium"},
        {ChromeBrowserType::Yandex, "AppData\\Local\\Yandex\\YandexBrowser\\User Data"},
        {ChromeBrowserType::Edge, "AppData\\Local\\Microsoft\\Edge\\User Data"},
        {ChromeBrowserType::EdgeBeta, "AppData\\Local\\Microsoft\\Edge Beta\\User Data"},
        {ChromeBrowserType::Opera, "AppData\\Roaming\\Opera Software\\Opera Stable"},
        {ChromeBrowserType::Vivaldi, "AppData\\Local\\Vivaldi\\User Data"},
        {ChromeBrowserType::Comet, "AppData\\Local\\Perplexity\\Comet\\User Data"}
    };

    const std::unordered_map<ChromeBrowserType, std::string>
    CHROME_BROWSER_TYPES =
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
        {ChromeBrowserType::Comet, "comet"}
    };

    const std::string PREFERENCES_FILE{"Preferences"};
    const std::string SECURE_PREFERENCES_FILE{"Secure Preferences"};
    const std::string EXTENSION_MANIFEST_FILE{"manifest.json"};
    const std::string EXTENSION_LOCALES_MESSAGES_FILE{"messages.json"};
    const std::string EXTENSIONS_DIR{"Extensions"};
    const std::string EXTENSION_LOCALES_DIR{"_locales"};

    /// @brief  Provides methods to collect Chrome browser extensions data.
    /// This class interacts with a Chrome extensions wrapper to gather information about installed Chrome extensions,
    /// such as their paths, identifiers, names, versions, and other relevant metadata.
    /// It formats the collected data into a structured JSON format for easy consumption and further processing.
    class ChromeExtensionsProvider
    {
        public:
            /// @brief Constructor that initializes the ChromeExtensionsProvider with a wrapper for Chrome extensions.
            /// @param chromeExtensionsWrapper A shared pointer to an IChromeExtensionsWrapper instance that provides
            /// methods to interact with Chrome extensions.
            /// This constructor allows the ChromeExtensionsProvider to use a specific implementation of IChromeExtensionsWrapper
            /// to collect data about Chrome extensions.
            explicit ChromeExtensionsProvider(
                std::shared_ptr<IBrowserExtensionsWrapper> chromeExtensionsWrapper);
            /// @brief Default constructor for ChromeExtensionsProvider, initializes with a default IChromeExtensionsWrapper.
            /// This constructor creates a ChromeExtensionsProvider instance using a default-constructed shared pointer to an
            /// IChromeExtensionsWrapper, allowing the provider to function without requiring an explicit wrapper instance.
            /// This is useful for scenarios where the wrapper is not provided externally, such as in unit tests or simple use cases.
            ChromeExtensionsProvider();
            /// brief Collects Chrome extensions data and returns it as a JSON object.
            /// @return A JSON object containing Chrome extensions data.
            nlohmann::json collect();

        private:
            /// @brief  Collects Chrome extensions from user profiles.
            /// @param extensions A reference to a ChromeExtensionList where the collected extensions will be stored.
            /// This method iterates through user profiles, checks for valid Chrome profiles, and retrieves extensions
            /// from each profile. It populates the provided ChromeExtensionList with the collected extensions.
            void getExtensionsFromProfiles(chrome::ChromeExtensionList& extensions);
            /// @brief Converts a list of Chrome extensions to a JSON format.
            /// @param extensions
            /// @return A JSON object representing the Chrome extensions data.
            nlohmann::json toJson(const chrome::ChromeExtensionList& extensions);
            /// @brief Checks if the given profile path is a valid Chrome profile.
            /// @param profilePath
            /// @return True if the profile path is valid, false otherwise.
            bool isValidChromeProfile(const std::string& profilePath);
            /// @brief Converts a JSON array to a string representation.
            /// This method iterates through the items in the JSON array and concatenates their string representations
            /// into a single string, separated by commas. It removes any trailing spaces or commas from the final string.
            /// @note This method is useful for converting JSON arrays into a human-readable
            /// @param jsonArray
            /// @return A string representation of the JSON array.
            std::string jsonArrayToString(const nlohmann::json& jsonArray);
            /// @brief Decodes a Base64 encoded string.
            /// @param input
            /// @return A decoded string from the Base64 input.
            std::string base64Decode(const std::string& input);
            /// @brief Checks if a string is in snake_case format.
            bool isSnakeCase(const std::string& s);
            /// @brief Localizes parameters for a Chrome extension.
            /// This method retrieves the locales for a Chrome extension and sets the current locale based on the
            /// default locale. It reads the messages file for the current locale and sets the extension's
            /// parameters accordingly, including the name and description.
            /// @param extension The Chrome extension for which to localize parameters.
            void localizeParameters(chrome::ChromeExtension& extension);
            /// @brief Converts a hash to a letter string or hex string.
            /// This method converts a hash represented as a byte array into a string format.
            /// It can convert the hash to a letter string or a hex string based on the specified
            /// parameters. The letter string is a human-readable representation of the hash,
            /// while the hex string is a hexadecimal representation of the hash.
            /// @param hash
            /// @param length
            /// @return A string representation of the hash.
            std::string hashToLetterString(const uint8_t* hash, size_t length);
            /// @brief Converts a hash to a hex string.
            /// This method converts a hash represented as a byte array into a hexadecimal string format.
            /// It iterates through each byte of the hash and converts it to a two-character hexadecimal
            /// representation, resulting in a string that represents the hash in hexadecimal format.
            /// @param hash
            /// @param length
            /// @return A hexadecimal string representation of the hash.
            std::string hashToHexString(const uint8_t* hash, size_t length);
            /// @brief Converts a WebKit timestamp to a Unix timestamp.
            /// This method takes a WebKit timestamp, which is in microseconds since the epoch,
            /// and converts it to a Unix timestamp in seconds. It handles potential errors such as
            /// invalid timestamps or out-of-range values, returning "0" in such cases.
            /// The conversion is done by subtracting the WebKit epoch offset and dividing by 10000000
            /// to convert microseconds to seconds.
            /// @param webkit_timestamp
            /// @return A string representing the Unix timestamp.
            std::string webkitToUnixTime(std::string webkit_timestamp);
            /// @brief Generates a unique identifier for a Chrome extension based on its key.
            /// This method takes the key of a Chrome extension and generates a unique identifier
            /// by hashing the key and converting it to a string format. The identifier is used to
            /// uniquely identify the extension within the browser's ecosystem.
            /// @param key
            /// @return A string representing the unique identifier for the extension.
            std::string generateIdentifier(const std::string& key);
            /// @brief Computes the SHA-256 hash of a file.
            /// @param filepath
            /// @return The generated SHA-256 hash as a hexadecimal string.
            std::string sha256File(const std::string& filepath);
            /// @brief Retrieves the profile name from the preferences files.
            std::string getProfileFromPreferences(const std::string& preferencesFilePath, const std::string& securePreferencesFilePath);
            /// @brief Parses the manifest JSON of a Chrome extension and populates the extension data structure.
            void parseManifest(nlohmann::json& manifestJson, chrome::ChromeExtension& extension);
            /// @brief Parses preference settings for a Chrome extension and populates the extension data structure.
            void parsePreferenceSettings(chrome::ChromeExtension& extension, const std::string& key, const nlohmann::json& value);
            /// @brief Retrieves common settings for a Chrome extension and populates the extension data structure.
            void getCommonSettings(chrome::ChromeExtension& extension, const std::string& manifestPath);
            /// @brief Retrieves extensions from the preferences file of a Chrome profile.
            chrome::ChromeExtensionList getExtensionsFromPreferences(const std::string& profilePath, const std::string& preferencesFilePath, const std::string& profileName);
            /// @brief Retrieves extensions from the given profile path that are referenced in the Preferences files.
            chrome::ChromeExtensionList getReferencedExtensions(const std::string& profilePath);
            /// @brief Retrieves extensions from the given profile path that are not referenced in the Preferences files.
            chrome::ChromeExtensionList getUnreferencedExtensions(const std::string& profilePath);
            /// @brief Retrieves extensions from the specified path and adds them to the provided extensions list.
            /// @param extensions
            /// @param path
            void getExtensionsFromPath(chrome::ChromeExtensionList& extensions, const std::string& path);

            std::shared_ptr<IBrowserExtensionsWrapper> m_chromeExtensionsWrapper;
            std::string m_currentBrowserType;
            std::string m_currentUid;
    };

} // namespace chrome
