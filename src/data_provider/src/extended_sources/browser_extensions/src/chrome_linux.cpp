/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "chrome_linux.hpp"
#include <tuple>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <algorithm>
#include "cppcodec/base64_rfc4648.hpp"
#include "openssl/sha.h"
#include "stringHelper.h"
#include "filesystemHelper.h"

namespace chrome
{

    ChromeExtensionsProvider::ChromeExtensionsProvider(std::shared_ptr<IChromeExtensionsWrapper> chromeExtensionsWrapper) : m_chromeExtensionsWrapper(std::move(chromeExtensionsWrapper))
    {
        m_userIds = m_chromeExtensionsWrapper->getUserIdsMap();
    }

    ChromeExtensionsProvider::ChromeExtensionsProvider() : m_chromeExtensionsWrapper(std::make_shared<ChromeExtensionsWrapper>())
    {
        m_userIds = m_chromeExtensionsWrapper->getUserIdsMap();
    }

    ChromeUserProfileList ChromeExtensionsProvider::getProfileDirs()
    {
        ChromeUserProfileList userProfiles;
        std::string homePath = m_chromeExtensionsWrapper->getHomePath();

        for (const auto& user : Utils::enumerateDir(homePath))
        {
            const std::string userHomePath = Utils::joinPaths(homePath, user);

            for (const auto& browser : kLinuxPathList)
            {
                std::string browserPath = std::get<1>(browser);
                const std::string profilePath = Utils::joinPaths(userHomePath, browserPath);

                if (!Utils::existsDir(profilePath))
                {
                    // std::cerr << "Chrome path does not exist\n";
                    continue;
                }

                userProfiles.emplace_back(profilePath);
            }
        }

        return userProfiles;
    }

    bool ChromeExtensionsProvider::isValidChromeProfile(const std::string& profilePath)
    {
        return Utils::existsRegular(Utils::joinPaths(profilePath, kPreferencesFile)) ||
               Utils::existsRegular(Utils::joinPaths(profilePath, kSecurePreferencesFile));
    }

    std::string ChromeExtensionsProvider::jsonArrayToString(const nlohmann::json& jsonArray)
    {
        std::string result;

        for (const auto& item : jsonArray)
        {
            result += item.get<std::string>() + ", ";
        }

        if (result.back() == ' ')
        {
            result.pop_back(); // Remove trailing comma
            result.pop_back();
        }

        return result;
    }

    bool ChromeExtensionsProvider::isSnakeCase(const std::string& s)
    {
        if (s.empty() || s.front() == '_' || s.back() == '_') return false;

        bool has_underscore = false;
        bool last_was_underscore = false;

        for (char c : s)
        {
            if (c == '_')
            {
                if (last_was_underscore) return false; // no double underscores

                has_underscore = true;
                last_was_underscore = true;
            }
            else
            {
                if (!std::isalnum(static_cast<unsigned char>(c))) return false;

                last_was_underscore = false;
            }
        }

        return has_underscore; // must contain at least one underscore
    }

    void ChromeExtensionsProvider::localizeParameters(ChromeExtension& extension)
    {
        std::string extensionPath(extension.path);
        std::string localesPath = Utils::joinPaths(extensionPath, kExtensionLocalesDir);
        std::string defaultLocalePath = Utils::joinPaths(localesPath, extension.default_locale);
        std::string messagesFilePath = Utils::joinPaths(defaultLocalePath, kExtensionLocaleMessagesFile);

        if (Utils::existsRegular(messagesFilePath))
        {
            std::string nameKey = Utils::rightTrim(Utils::leftTrim(extension.name, "__MSG_"), "__");
            std::string descriptionKey = Utils::rightTrim(Utils::leftTrim(extension.description, "__MSG_"), "__");;

            if (isSnakeCase(nameKey))
            {
                nameKey = Utils::toLowerCase(nameKey);
            }

            if (isSnakeCase(descriptionKey))
            {
                descriptionKey = Utils::toLowerCase(descriptionKey);
            }

            std::ifstream messagesFile(messagesFilePath);
            nlohmann::json messagesJson = nlohmann::json::parse(messagesFile);
            extension.name = messagesJson.contains(nameKey) ? messagesJson[nameKey]["message"].get<std::string>() : extension.name;
            extension.description = messagesJson.contains(descriptionKey) ? messagesJson[descriptionKey]["message"].get<std::string>() : extension.description;
        }
    }

    std::string ChromeExtensionsProvider::hashToLetterString(const uint8_t* hash, size_t length)
    {
        std::string result;
        result.reserve(length * 2); // two letters per byte (high and low nibble)

        for (size_t i = 0; i < length; ++i)
        {
            uint8_t byte = hash[i];
            // high nibble
            result.push_back('a' + ((byte >> 4) & 0x0F));
            // low nibble
            result.push_back('a' + (byte & 0x0F));
        }

        return result;
    }

    std::string ChromeExtensionsProvider::generateIdentifier(const std::string& key)
    {
        auto decodedVector = cppcodec::base64_rfc4648::decode(key);
        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256(decodedVector.data(), decodedVector.size(), hash);
        std::string letters_string = hashToLetterString(hash, SHA256_DIGEST_LENGTH);
        return letters_string.substr(0, 32);
    }

    std::string ChromeExtensionsProvider::hashToHexString(const uint8_t* hash, size_t length)
    {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');

        for (size_t i = 0; i < length; ++i)
        {
            oss << std::setw(2) << static_cast<int>(hash[i]);
        }

        return oss.str();
    }

    std::string ChromeExtensionsProvider::sha256File(const std::string& filepath)
    {
        std::ifstream file(filepath, std::ios::binary);

        if (!file)
        {
            throw std::runtime_error("Cannot open file: " + filepath);
        }

        SHA256_CTX sha256;
        SHA256_Init(&sha256);

        std::vector<char> buffer(8192);

        while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0)
        {
            SHA256_Update(&sha256, buffer.data(), file.gcount());
        }

        uint8_t hash[SHA256_DIGEST_LENGTH];
        SHA256_Final(hash, &sha256);

        // Reuse the same hex function if needed
        return hashToHexString(hash, SHA256_DIGEST_LENGTH);
    }

    std::string ChromeExtensionsProvider::webkitToUnixTime(std::string webkit_timestamp)
    {
        int64_t timestamp = std::stoll(webkit_timestamp);
        std::time_t unix_timestap = (timestamp - 11644473600000000LL) / 1000000;
        return std::to_string(unix_timestap);
    }

    void ChromeExtensionsProvider::parseManifest(nlohmann::json& manifestJson, ChromeExtension& extension)
    {
        extension.name = manifestJson.contains("name") ? manifestJson["name"].get<std::string>() : "";
        extension.update_url = manifestJson.contains("update_url") ? manifestJson["update_url"].get<std::string>() : "";
        extension.version = manifestJson.contains("version") ? manifestJson["version"].get<std::string>() : "";
        extension.author = (manifestJson.contains("author") && manifestJson["author"].is_string()) ? manifestJson["author"].get<std::string>() : "";
        extension.default_locale = manifestJson.contains("default_locale") ? manifestJson["default_locale"].get<std::string>() : "";
        extension.current_locale = manifestJson.contains("current_locale") ? manifestJson["current_locale"].get<std::string>() : "";

        if (manifestJson.contains("background") && manifestJson["background"].contains("persistent"))
        {
            bool isPersistent = manifestJson["background"]["persistent"].get<bool>();
            extension.persistent = isPersistent ? "1" : "0";
        }
        else
        {
            extension.persistent = "0";
        }

        extension.description = manifestJson.contains("description") ? manifestJson["description"].get<std::string>() : "";
        extension.permissions = manifestJson.contains("permissions") ? jsonArrayToString(manifestJson["permissions"]) : "";
        extension.optional_permissions = manifestJson.contains("optional_permissions") ? jsonArrayToString(manifestJson["optional_permissions"]) : "";
        extension.key = manifestJson.contains("key") ? manifestJson["key"].get<std::string>() : "";

        localizeParameters(extension);
    }

    void ChromeExtensionsProvider::parsePreferenceSettings(ChromeExtension& extension, const std::string& key, const nlohmann::json& value)
    {
        extension.state = value.contains("state") ? std::to_string(value["state"].get<int>()) : "";

        if (value.contains("from_webstore"))
        {
            extension.from_webstore = value["from_webstore"].get<bool>() ? "true" : "false";
        }
        else
        {
            extension.from_webstore = "";
        }

        extension.install_time = value.contains("first_install_time") ? value["first_install_time"].get<std::string>() : "0";
        extension.install_timestamp = webkitToUnixTime(extension.install_time);
        extension.referenced_identifier = key;
    }

    void ChromeExtensionsProvider::getCommonSettings(ChromeExtension& extension, const std::string& manifestPath)
    {
        std::string absoluteAppPath = Utils::joinPaths("/", Utils::removePrefix(manifestPath, Utils::getParentPath(m_chromeExtensionsWrapper->getHomePath())));

        for (const auto& browser : kLinuxPathList)
        {
            if (absoluteAppPath.find(std::get<1>(browser)) != std::string::npos)
            {
                extension.browser_type = kChromeBrowserTypeToString.at(std::get<0>(browser));
                break;
            }
        }

        for (const auto& user : m_userIds)
        {
            if (Utils::startsWith(absoluteAppPath, user.first))
            {
                extension.uid = user.second;
                break;
            }
        }

        extension.manifest_hash = sha256File(manifestPath);
    }

    ChromeExtensionList ChromeExtensionsProvider::getExtensionsFromPreferences(const std::string& profilePath, const std::string& preferencesFilePath, const std::string& profileName)
    {
        if (!Utils::existsRegular(preferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << preferencesFilePath << std::endl;
            return ChromeExtensionList();
        }

        std::ifstream preferencesFile(preferencesFilePath);
        nlohmann::json preferencesJson = nlohmann::json::parse(preferencesFile);

        const nlohmann::json& settings = preferencesJson["extensions"]["settings"];
        ChromeExtensionList extensions;

        for (const auto& item : settings.items())
        {
            if (item.value().contains("path"))
            {
                std::string extensionPath(item.value()["path"]);

                if (!Utils::isAbsolutePath(extensionPath))
                {
                    extensionPath = Utils::joinPaths(Utils::joinPaths(profilePath, kExtensionsDir), extensionPath);
                }

                std::string manifestPath = Utils::joinPaths(extensionPath, kExtensionManifestFile);

                if (Utils::existsDir(extensionPath) && Utils::existsRegular(manifestPath))
                {
                    ChromeExtension extension;

                    extension.profile = profileName;
                    extension.profile_path = profilePath;
                    extension.path = extensionPath;
                    extension.referenced = std::to_string(1);

                    getCommonSettings(extension, manifestPath);
                    parsePreferenceSettings(extension, item.key(), item.value());

                    std::ifstream manifestFile(manifestPath);
                    nlohmann::json manifestJson = nlohmann::json::parse(manifestFile);
                    parseManifest(manifestJson, extension);

                    extension.identifier = generateIdentifier(extension.key);

                    extensions.emplace_back(extension);
                }
            }
        }

        return extensions;
    }

    std::string ChromeExtensionsProvider::getProfileFromPreferences(const std::string& preferencesFilePath, const std::string& securePreferencesFilePath)
    {
        std::string profileName = "";

        if (!Utils::existsRegular(preferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << preferencesFilePath << std::endl;
            return profileName;
        }

        if (!Utils::existsRegular(securePreferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << preferencesFilePath << std::endl;
            return profileName;
        }

        std::ifstream preferencesFile(preferencesFilePath);
        std::ifstream securePreferencesFile(securePreferencesFilePath);

        nlohmann::json preferencesJson = nlohmann::json::parse(preferencesFile);
        nlohmann::json securePreferencesJson = nlohmann::json::parse(securePreferencesFile);

        if (preferencesJson.contains("profile") && preferencesJson["profile"].contains("name"))
        {
            profileName = preferencesJson["profile"]["name"].get<std::string>();
        }
        else if (securePreferencesJson.contains("profile") && securePreferencesJson["profile"].contains("name"))
        {
            profileName = securePreferencesJson["profile"]["name"].get<std::string>();
        }

        return profileName;
    }

    ChromeExtensionList ChromeExtensionsProvider::getReferencedExtensions(const std::string& profilePath)
    {
        std::string preferencesFilePath = Utils::joinPaths(profilePath, kPreferencesFile);
        std::string securePreferencesFilePath = Utils::joinPaths(profilePath, kSecurePreferencesFile);
        std::string profileName = getProfileFromPreferences(preferencesFilePath, securePreferencesFilePath);

        ChromeExtensionList preferencesFileExtensions = getExtensionsFromPreferences(profilePath, preferencesFilePath, profileName);
        ChromeExtensionList securePreferencesFileExtensions = getExtensionsFromPreferences(profilePath, securePreferencesFilePath, profileName);

        // Only add to extension list the extensions that are not already in the list
        for (const auto& securePreferencesExtension : securePreferencesFileExtensions)
        {
            auto it = std::find_if(preferencesFileExtensions.begin(), preferencesFileExtensions.end(), [&securePreferencesExtension](const auto & preferencesExtension)
            {
                return preferencesExtension.path == securePreferencesExtension.path;
            });

            if (it == preferencesFileExtensions.end())
            {
                // This extension should be added to list
                preferencesFileExtensions.emplace_back(securePreferencesExtension);
            }
        }

        return preferencesFileExtensions;
    }

    ChromeExtensionList ChromeExtensionsProvider::getUnreferencedExtensions(const std::string& profilePath)
    {
        std::string extensionPath = Utils::joinPaths(profilePath, kExtensionsDir);

        if (!Utils::existsDir(extensionPath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Extensions folder does not exist: " << extensionPath << std::endl;
            return ChromeExtensionList();
        }

        std::string preferencesFilePath = Utils::joinPaths(profilePath, kPreferencesFile);
        std::string securePreferencesFilePath = Utils::joinPaths(profilePath, kSecurePreferencesFile);

        if (!Utils::existsRegular(preferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << preferencesFilePath << std::endl;
            return ChromeExtensionList();
        }

        if (!Utils::existsRegular(securePreferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << securePreferencesFilePath << std::endl;
            return ChromeExtensionList();
        }

        std::ifstream preferencesFile(preferencesFilePath);
        nlohmann::json preferencesJson = nlohmann::json::parse(preferencesFile);
        std::string profileName = getProfileFromPreferences(preferencesFilePath, securePreferencesFilePath);
        ChromeExtensionList extensions;

        for (auto subDir : Utils::enumerateDir(extensionPath))
        {
            subDir = Utils::joinPaths(extensionPath, subDir);

            if (!Utils::existsDir(subDir)) continue;

            for (auto subSubDir : Utils::enumerateDir(subDir))
            {
                subSubDir = Utils::joinPaths(subDir, subSubDir);

                if (!Utils::existsDir(subSubDir)) continue;

                std::string manifestPath = Utils::joinPaths(subSubDir, kExtensionManifestFile);

                if (Utils::existsRegular(manifestPath))
                {
                    ChromeExtension extension;

                    extension.profile = profileName;
                    extension.profile_path = profilePath;
                    extension.path = subSubDir;
                    extension.referenced = "0";
                    extension.install_timestamp = "0";

                    getCommonSettings(extension, manifestPath);

                    std::ifstream manifestFile(manifestPath);
                    nlohmann::json manifestJson = nlohmann::json::parse(manifestFile);
                    parseManifest(manifestJson, extension);

                    extension.identifier = generateIdentifier(extension.key);

                    extensions.emplace_back(extension);
                }
            }
        }

        return extensions;
    }

    void ChromeExtensionsProvider::printExtensions(const ChromeExtensionList& extensions)
    {
        for (const auto& extension : extensions)
        {
            std::cout << "<-------------------------------Extension----------------------------->" << std::endl
                      << extension.author << std::endl
                      << extension.browser_type << std::endl
                      << extension.current_locale << std::endl
                      << extension.default_locale << std::endl
                      << extension.description << std::endl
                      << extension.from_webstore << std::endl
                      << extension.identifier << std::endl
                      << extension.install_time << std::endl
                      << extension.install_timestamp << std::endl
                      << extension.manifest_hash << std::endl
                      << extension.name << std::endl
                      << extension.optional_permissions << std::endl
                      << extension.path << std::endl
                      << extension.permissions << std::endl
                      << extension.persistent << std::endl
                      << extension.profile << std::endl
                      << extension.profile_path << std::endl
                      << extension.referenced << std::endl
                      << extension.referenced_identifier << std::endl
                      << extension.state << std::endl
                      << extension.uid << std::endl
                      << extension.update_url << std::endl
                      << extension.version << std::endl
                      << extension.permissions_json << std::endl
                      << extension.optional_permissions_json << std::endl
                      << extension.manifest_json << std::endl
                      << extension.key << std::endl;
        }
    }

    nlohmann::json ChromeExtensionsProvider::toJson(const ChromeExtensionList& extensions)
    {
        nlohmann::json results = nlohmann::json::array();

        for (auto& extension : extensions)
        {
            nlohmann::json entry;
            entry["author"] = extension.author;
            entry["browser_type"] = extension.browser_type;
            entry["current_locale"] = extension.current_locale;
            entry["default_locale"] = extension.default_locale;
            entry["description"] = extension.description;
            entry["from_webstore"] = extension.from_webstore;
            entry["identifier"] = extension.identifier;
            entry["install_time"] = extension.install_time;
            entry["install_timestamp"] = extension.install_timestamp;
            entry["manifest_hash"] = extension.manifest_hash;
            entry["name"] = extension.name;
            entry["optional_permissions"] = extension.optional_permissions;
            entry["path"] = extension.path;
            entry["permissions"] = extension.permissions;
            entry["persistent"] = extension.persistent;
            entry["profile"] = extension.profile;
            entry["profile_path"] = extension.profile_path;
            entry["referenced"] = extension.referenced;
            entry["referenced_identifier"] = extension.referenced_identifier;
            entry["state"] = extension.state;
            entry["uid"] = extension.uid;
            entry["update_url"] = extension.update_url;
            entry["version"] = extension.version;
            results.push_back(std::move(entry));
        }

        return results;
    }

    void ChromeExtensionsProvider::getExtensionsFromPath(ChromeExtensionList& extensions, const std::string& path)
    {
        ChromeExtensionList referencedExtensions = getReferencedExtensions(path);
        extensions.insert(extensions.end(), referencedExtensions.begin(), referencedExtensions.end());

        ChromeExtensionList unreferencedExtensions = getUnreferencedExtensions(path);

        // Only add to extension list the unreferenced extensions that are not already in the list
        for (const auto& unreferencedExtension : unreferencedExtensions)
        {
            auto it = std::find_if(referencedExtensions.begin(), referencedExtensions.end(), [&unreferencedExtension](const auto & referencedExtension)
            {
                return referencedExtension.path == unreferencedExtension.path;
            });

            if (it == referencedExtensions.end())
            {
                // This extension should be added to list
                extensions.emplace_back(unreferencedExtension);
            }
        }
    }

    void ChromeExtensionsProvider::getExtensionsFromProfiles(ChromeExtensionList& extensions, const ChromeUserProfileList& profilePaths)
    {
        for (auto& profilePath : profilePaths)
        {
            if (isValidChromeProfile(profilePath))
            {
                getExtensionsFromPath(extensions, profilePath);
            }
            else
            {
                for (auto subDirectory : Utils::enumerateDir(profilePath))
                {
                    subDirectory = Utils::joinPaths(profilePath, subDirectory);

                    if (Utils::existsDir(subDirectory) && isValidChromeProfile(subDirectory))
                    {
                        getExtensionsFromPath(extensions, subDirectory);
                    }
                }
            }
        }
    }

    nlohmann::json ChromeExtensionsProvider::collect()
    {
        auto profilePaths = getProfileDirs();
        ChromeExtensionList extensions;
        getExtensionsFromProfiles(extensions, profilePaths);

        return toJson(extensions);
    }


} // namespace chrome