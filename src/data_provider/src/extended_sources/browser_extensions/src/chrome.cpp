/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "chrome.hpp"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <limits>
#include <openssl/evp.h>
#include <vector>
#include <string>
#include "stringHelper.h"
#include "filesystemHelper.h"
#include "json_field_helpers.hpp"

#define MAX_PATH_LENGTH 4096

using JsonFieldHelpers::getBoolField;
using JsonFieldHelpers::getObjectField;
using JsonFieldHelpers::getStringField;

namespace chrome
{
    ChromeExtensionsProvider::ChromeExtensionsProvider(std::shared_ptr<IBrowserExtensionsWrapper> chromeExtensionsWrapper) : m_chromeExtensionsWrapper(std::move(chromeExtensionsWrapper))
    {
    }

    ChromeExtensionsProvider::ChromeExtensionsProvider() : m_chromeExtensionsWrapper(std::make_shared<BrowserExtensionsWrapper>())
    {
    }

    bool ChromeExtensionsProvider::isValidChromeProfile(const std::string& profilePath)
    {
        if (profilePath.empty() ||
                profilePath.find("..") != std::string::npos ||
                profilePath.length() > MAX_PATH_LENGTH
           )
        {
            return false;
        }

        return Utils::existsRegular(Utils::joinPaths(profilePath, PREFERENCES_FILE)) ||
               Utils::existsRegular(Utils::joinPaths(profilePath, SECURE_PREFERENCES_FILE));
    }

    std::string ChromeExtensionsProvider::jsonArrayToString(const nlohmann::json& jsonArray)
    {
        std::string result;

        for (const auto& item : jsonArray)
        {
            if (item.is_string())
            {
                result += item.get<std::string>() + ", ";
            }
        }

        if (!result.empty() && result.back() == ' ')
        {
            result.pop_back(); // Remove trailing space

            if (!result.empty() && result.back() == ',')
            {
                result.pop_back(); // Remove trailing comma
            }
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

    bool ChromeExtensionsProvider::isValidLocaleName(const std::string& locale)
    {
        return !locale.empty() && std::all_of(locale.begin(), locale.end(), [](unsigned char c)
        {
            return std::isalnum(c) || c == '_' || c == '-';
        });
    }

    void ChromeExtensionsProvider::localizeParameters(ChromeExtension& extension)
    {
        if (!isValidLocaleName(extension.default_locale))
        {
            return;
        }

        const std::string& extensionPath = extension.path;
        std::string localesPath = Utils::joinPaths(extensionPath, EXTENSION_LOCALES_DIR);
        std::string defaultLocalePath = Utils::joinPaths(localesPath, extension.default_locale);
        std::string messagesFilePath = Utils::joinPaths(defaultLocalePath, EXTENSION_LOCALES_MESSAGES_FILE);

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
            const nlohmann::json messagesJson = nlohmann::json::parse(messagesFile, nullptr, false, true);

            if (messagesJson.is_discarded())
            {
                return;
            }

            const auto localize = [&messagesJson](const std::string & key, std::string & field)
            {
                const auto& entry = getObjectField(messagesJson, key.c_str());
                const auto it = entry.find("message");

                if (it != entry.end() && it->is_string())
                {
                    field = it->get<std::string>();
                }
            };

            localize(nameKey, extension.name);
            localize(descriptionKey, extension.description);
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

    std::string ChromeExtensionsProvider::base64Decode(const std::string& input)
    {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string decoded;
        std::vector<int> T(256, -1);

        // Build lookup table
        for (int i = 0; i < 64; i++) T[chars[i]] = i;

        int val = 0, valb = -8;

        for (unsigned char c : input)
        {
            if (T[c] == -1) break;

            val = (val << 6) + T[c];
            valb += 6;

            if (valb >= 0)
            {
                decoded.push_back(char((val >> valb) & 0xFF));
                valb -= 8;
            }
        }

        return decoded;
    }

    std::string ChromeExtensionsProvider::generateIdentifier(const std::string& key)
    {
        // Decode to string first
        std::string decodedString = base64Decode(key);

        if (decodedString.empty())
        {
            return "";
        }

        // Convert to vector<uint8_t> to match original behavior exactly
        std::vector<uint8_t> decodedVector(decodedString.begin(), decodedString.end());

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        if (!mdctx)
        {
            return "";
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return "";
        }

        if (EVP_DigestUpdate(mdctx, decodedVector.data(), decodedVector.size()) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return "";
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return "";
        }

        EVP_MD_CTX_free(mdctx);

        std::string letters_string = hashToLetterString(hash, hashLen);
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
            return "";
        }

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();

        if (!mdctx)
        {
            return "";
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return "";
        }

        std::vector<char> buffer(8192);

        while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0)
        {
            if (EVP_DigestUpdate(mdctx, buffer.data(), file.gcount()) != 1)
            {
                EVP_MD_CTX_free(mdctx);
                return "";
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int length = 0;

        if (EVP_DigestFinal_ex(mdctx, hash, &length) != 1)
        {
            EVP_MD_CTX_free(mdctx);
            return "";
        }

        EVP_MD_CTX_free(mdctx);

        return hashToHexString(hash, length);
    }

    std::string ChromeExtensionsProvider::webkitToUnixTime(std::string webkit_timestamp)
    {
        try
        {
            if (webkit_timestamp.empty() || !std::all_of(webkit_timestamp.begin(), webkit_timestamp.end(), ::isdigit))
            {
                return "";
            }

            int64_t timestamp = std::stoll(webkit_timestamp);

            if (timestamp < 11644473600000000LL || timestamp > 253402300799000000LL)
            {
                return "";
            }

            std::time_t unix_timestamp = (timestamp - 11644473600000000LL) / 1000000;
            return std::to_string(unix_timestamp);
        }
        catch (const std::exception& e)
        {
            return "";
        }
    }

    void ChromeExtensionsProvider::parseManifest(nlohmann::json& manifestJson, ChromeExtension& extension)
    {
        extension.name = getStringField(manifestJson, "name");
        extension.update_url = getStringField(manifestJson, "update_url");
        extension.version = getStringField(manifestJson, "version");
        extension.author = getStringField(manifestJson, "author");
        extension.default_locale = getStringField(manifestJson, "default_locale");
        extension.current_locale = getStringField(manifestJson, "current_locale");
        extension.persistent = getBoolField(getObjectField(manifestJson, "background"), "persistent", false) ? "1" : "0";
        extension.description = getStringField(manifestJson, "description");
        extension.permissions = manifestJson.contains("permissions") ? jsonArrayToString(manifestJson["permissions"]) : "";
        extension.optional_permissions = manifestJson.contains("optional_permissions") ? jsonArrayToString(manifestJson["optional_permissions"]) : "";
        extension.key = getStringField(manifestJson, "key");

        localizeParameters(extension);
    }

    void ChromeExtensionsProvider::parsePreferenceSettings(ChromeExtension& extension, const std::string& key, const nlohmann::json& value)
    {
        const auto stateIt = value.find("state");
        extension.state = "1";

        if (stateIt != value.end() && stateIt->is_number_integer())
        {
            extension.state = std::to_string(stateIt->get<int>());
        }
        else if (stateIt != value.end() && stateIt->is_number_float())
        {
            const auto state = stateIt->get<double>();

            if (state >= std::numeric_limits<int>::min() && state <= std::numeric_limits<int>::max())
            {
                extension.state = std::to_string(static_cast<int>(state));
            }
        }

        extension.from_webstore = getBoolField(value, "from_webstore", false) ? "1" : "0";
        extension.install_time = getStringField(value, "first_install_time");
        extension.install_timestamp = webkitToUnixTime(extension.install_time);
        extension.referenced_identifier = key;
    }

    void ChromeExtensionsProvider::getCommonSettings(ChromeExtension& extension, const std::string& manifestPath)
    {
        extension.browser_type = m_currentBrowserType;
        extension.uid = m_currentUid;
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
        nlohmann::json preferencesJson;

        try
        {
            preferencesJson = nlohmann::json::parse(preferencesFile);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            // Log error and return empty list
            return ChromeExtensionList();
        }
        catch (const std::exception& e)
        {
            return ChromeExtensionList();
        }

        const nlohmann::json& settings = getObjectField(getObjectField(preferencesJson, "extensions"), "settings");
        ChromeExtensionList extensions;

        for (const auto& item : settings.items())
        {
            if (item.value().contains("path"))
            {
                std::string extensionPath = getStringField(item.value(), "path");

                if (!Utils::isAbsolutePath(extensionPath))
                {
                    if (extensionPath.find("..") != std::string::npos ||
                            extensionPath.find("//") != std::string::npos ||
                            extensionPath.empty() || extensionPath.length() > MAX_PATH_LENGTH)
                    {
                        continue;
                    }

                    extensionPath = Utils::joinPaths(Utils::joinPaths(profilePath, EXTENSIONS_DIR), extensionPath);
                }

                std::string manifestPath = Utils::joinPaths(extensionPath, EXTENSION_MANIFEST_FILE);

                if (Utils::existsDir(extensionPath) && Utils::existsRegular(manifestPath))
                {
                    ChromeExtension extension;

                    extension.profile = profileName;
                    extension.profile_path = profilePath;
                    extension.path = std::move(extensionPath);
                    extension.referenced = std::to_string(1);

                    getCommonSettings(extension, manifestPath);

                    try
                    {
                        parsePreferenceSettings(extension, item.key(), item.value());

                        std::ifstream manifestFile(manifestPath);
                        nlohmann::json manifestJson = nlohmann::json::parse(manifestFile, nullptr, true, true);

                        parseManifest(manifestJson, extension);

                        extension.identifier = generateIdentifier(extension.key);
                    }
                    catch (const std::exception& e)
                    {
                        continue; // Skip this extension and continue with next
                    }

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

        nlohmann::json preferencesJson;

        try
        {
            preferencesJson = nlohmann::json::parse(preferencesFile);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            return "";
        }

        nlohmann::json securePreferencesJson;

        try
        {
            securePreferencesJson = nlohmann::json::parse(securePreferencesFile);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            return "";
        }

        profileName = getStringField(getObjectField(preferencesJson, "profile"), "name");

        if (profileName.empty())
        {
            profileName = getStringField(getObjectField(securePreferencesJson, "profile"), "name");
        }

        return profileName;
    }

    ChromeExtensionList ChromeExtensionsProvider::getReferencedExtensions(const std::string& profilePath)
    {
        std::string preferencesFilePath = Utils::joinPaths(profilePath, PREFERENCES_FILE);
        std::string securePreferencesFilePath = Utils::joinPaths(profilePath, SECURE_PREFERENCES_FILE);
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
        std::string extensionPath = Utils::joinPaths(profilePath, EXTENSIONS_DIR);

        if (!Utils::existsDir(extensionPath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Extensions folder does not exist: " << extensionPath << std::endl;
            return {};
        }

        std::string preferencesFilePath = Utils::joinPaths(profilePath, PREFERENCES_FILE);
        std::string securePreferencesFilePath = Utils::joinPaths(profilePath, SECURE_PREFERENCES_FILE);

        if (!Utils::existsRegular(preferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << preferencesFilePath << std::endl;
            return {};
        }

        if (!Utils::existsRegular(securePreferencesFilePath))
        {
            // TODO: Improve handling this error.
            // std::cerr << "Preferences file does not exist: " << securePreferencesFilePath << std::endl;
            return {};
        }

        std::string profileName = getProfileFromPreferences(preferencesFilePath, securePreferencesFilePath);
        ChromeExtensionList extensions;

        for (const auto& entry : Utils::enumerateDir(extensionPath))
        {
            const std::string subDir = Utils::joinPaths(extensionPath, entry);

            if (!Utils::existsDir(subDir)) continue;

            for (const auto& subEntry : Utils::enumerateDir(subDir))
            {
                std::string subSubDir = Utils::joinPaths(subDir, subEntry);

                if (!Utils::existsDir(subSubDir)) continue;

                std::string manifestPath = Utils::joinPaths(subSubDir, EXTENSION_MANIFEST_FILE);

                if (Utils::existsRegular(manifestPath))
                {
                    ChromeExtension extension;

                    extension.profile = profileName;
                    extension.profile_path = profilePath;
                    extension.path = std::move(subSubDir);
                    extension.referenced = "0";
                    extension.install_timestamp = "";

                    getCommonSettings(extension, manifestPath);

                    try
                    {
                        std::ifstream manifestFile(manifestPath);
                        nlohmann::json manifestJson = nlohmann::json::parse(manifestFile, nullptr, true, true);

                        parseManifest(manifestJson, extension);

                        extension.identifier = generateIdentifier(extension.key);
                    }
                    catch (const std::exception& e)
                    {
                        continue; // Skip this extension and continue with next
                    }

                    extensions.emplace_back(extension);
                }
            }
        }

        return extensions;
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

    void ChromeExtensionsProvider::getExtensionsFromProfiles(ChromeExtensionList& extensions)
    {
        std::string homePath = m_chromeExtensionsWrapper->getHomePath();

        for (const auto& user : Utils::enumerateDir(homePath))
        {
            // ignore ".", ".." and hidden directories
            if (Utils::startsWith(user, "."))
            {
                continue;
            }

            m_currentUid = m_chromeExtensionsWrapper->getUserId(user);
            const std::string userHomePath = Utils::joinPaths(homePath, user);

#if defined(_WIN32) || defined(_WIN64)

            for (const auto& [browserType, browserPath] : WINDOWS_PATH_LIST)
#elif defined(__APPLE__) && defined(__MACH__)

            for (const auto& [browserType, browserPath] : MACOS_PATH_LIST)
#elif defined(__linux__)
            for (const auto& [browserType, browserPath] : LINUX_PATH_LIST)
#endif
            {
                const std::string profilePath = Utils::joinPaths(userHomePath, browserPath);

                if (!Utils::existsDir(profilePath))
                {
                    // std::cerr << "Chrome path does not exist\n";
                    continue;
                }

                m_currentBrowserType = CHROME_BROWSER_TYPES.at(browserType);

                // The profile path exists, now let's find the profile.
                if (isValidChromeProfile(profilePath))
                {
                    getExtensionsFromPath(extensions, profilePath);
                }
                else
                {
                    for (const auto& entry : Utils::enumerateDir(profilePath))
                    {
                        const std::string subDirectory = Utils::joinPaths(profilePath, entry);

                        if (Utils::existsDir(subDirectory) && isValidChromeProfile(subDirectory))
                        {
                            getExtensionsFromPath(extensions, subDirectory);
                        }
                    }
                }
            }
        }
    }

    nlohmann::json ChromeExtensionsProvider::collect()
    {
        ChromeExtensionList extensions;
        getExtensionsFromProfiles(extensions);

        return toJson(extensions);
    }


} // namespace chrome
