/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agent_credential_store.hpp"

#include "ci_logging_helper.hpp"

#include <evpHelper.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>
#include <vector>

#include <json.hpp>

#ifndef WIN32
#include <sys/stat.h>
#endif

namespace
{
    void logWarn(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_WARNING, message);
    }

    void logDebug(const std::string& message)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, message);
    }

    /// @brief Hex-encode raw bytes.
    ///
    /// The ciphertext is binary and JSON cannot carry it raw. Hex rather than base64
    /// because there is no reusable base64 in the agent's dependencies, and the values
    /// are a user name and a token, so doubling a few dozen bytes costs nothing.
    std::string toHex(const std::vector<char>& bytes)
    {
        static constexpr char DIGITS[] = "0123456789abcdef";

        std::string hex;
        hex.reserve(bytes.size() * 2);

        for (const auto byte : bytes)
        {
            const auto value {static_cast<unsigned char>(byte)};
            hex.push_back(DIGITS[value >> 4]);
            hex.push_back(DIGITS[value & 0x0F]);
        }

        return hex;
    }

    /// @brief Decode a hex string, reporting anything that is not one.
    /// @return True when @p hex was a well-formed even-length hex string.
    bool fromHex(const std::string& hex, std::vector<char>& bytes)
    {
        if (hex.empty() || (hex.size() % 2) != 0)
        {
            return false;
        }

        const auto nibble = [](const char character, unsigned char& value)
        {
            if (character >= '0' && character <= '9')
            {
                value = static_cast<unsigned char>(character - '0');
            }
            else if (character >= 'a' && character <= 'f')
            {
                value = static_cast<unsigned char>(character - 'a' + 10);
            }
            else if (character >= 'A' && character <= 'F')
            {
                value = static_cast<unsigned char>(character - 'A' + 10);
            }
            else
            {
                return false;
            }

            return true;
        };

        bytes.clear();
        bytes.reserve(hex.size() / 2);

        for (std::size_t index = 0; index < hex.size(); index += 2)
        {
            unsigned char high {0};
            unsigned char low {0};

            if (!nibble(hex[index], high) || !nibble(hex[index + 1], low))
            {
                bytes.clear();
                return false;
            }

            bytes.push_back(static_cast<char>((high << 4) | low));
        }

        return true;
    }

    /// @brief Read the store document, or nothing when there is no store to read.
    ///
    /// Distinguishes "no store" from "a store that cannot be read": the first is an
    /// ordinary state and the second is reported by the caller.
    enum class LoadOutcome
    {
        Loaded,  ///< The document was read and is an object.
        Absent,  ///< There is no store file.
        Unusable ///< There is one, and it could not be read or parsed.
    };

    LoadOutcome loadStore(const std::string& path, nlohmann::json& document)
    {
        std::error_code error;

        const auto present {std::filesystem::exists(path, error)};

        if (error)
        {
            // A permissions or mount problem on the directory sets this. Reporting it as
            // an absent store would surface only as a 401 on the reference, which points
            // an operator at the credential rather than at the file they cannot read.
            return LoadOutcome::Unusable;
        }

        if (!present)
        {
            return LoadOutcome::Absent;
        }

        const auto size {std::filesystem::file_size(path, error)};

        if (error)
        {
            return LoadOutcome::Unusable;
        }

        if (size > containerimages::MAX_CREDENTIAL_STORE_SIZE)
        {
            return LoadOutcome::Unusable;
        }

        std::ifstream file {path, std::ios::binary};

        if (!file.is_open())
        {
            return LoadOutcome::Unusable;
        }

        std::ostringstream contents;
        contents << file.rdbuf();

        // Non-throwing parse, and copy-initialized: brace-initializing a json from a json
        // selects its initializer-list constructor and would wrap the document in an array.
        auto parsed = nlohmann::json::parse(contents.str(), nullptr, false);

        if (!parsed.is_object())
        {
            return LoadOutcome::Unusable;
        }

        document = std::move(parsed);

        return LoadOutcome::Loaded;
    }

    /// @brief Restrict the store so only the agent's own account can read it.
    ///
    /// This is the control the design actually relies on, so a failure to apply it is
    /// reported rather than ignored.
    bool restrictPermissions(const std::string& path)
    {
#ifndef WIN32
        // 0640: agent daemons run as root, so nothing needs group write and no one else
        // needs any access. Set explicitly rather than left to the umask.
        if (::chmod(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP) != 0)
        {
            return false;
        }

        return true;
#else
        // Never reached: put() refuses on Windows before it gets here. Restricting the
        // file would need an explicit DACL granting only SYSTEM and BUILTIN\Administrators
        // with inheritance disabled, because a file inheriting its parent's ACL under the
        // installation directory is readable by Users. Registry support is not offered on
        // Windows, so that work is not done and no credential is written there.
        (void)path;
        return false;
#endif
    }
} // namespace

namespace containerimages
{
    AgentCredentialStore::AgentCredentialStore(std::string path)
        : m_path {std::move(path)}
    {
    }

    std::optional<Secret> AgentCredentialStore::get(const std::string& family, const std::string& key) const
    {
        nlohmann::json document;

        switch (loadStore(m_path, document))
        {
            case LoadOutcome::Absent:
                logDebug("No credential store at '" + m_path + "', continuing without a credential.");
                return std::nullopt;

            case LoadOutcome::Unusable:
                logWarn("The credential store at '" + m_path +
                        "' exists but could not be read. Continuing without a credential.");
                return std::nullopt;

            case LoadOutcome::Loaded: break;
        }

        const auto families {document.find(family)};

        if (families == document.end() || !families->is_object())
        {
            return std::nullopt;
        }

        const auto entry {families->find(key)};

        if (entry == families->end() || !entry->is_string())
        {
            return std::nullopt;
        }

        std::vector<char> encrypted;

        if (!fromHex(entry->get<std::string>(), encrypted))
        {
            logWarn("The credential stored for family '" + family +
                    "' is malformed. Continuing without a credential.");
            return std::nullopt;
        }

        try
        {
            std::string decrypted;
            EVPHelper<>().decryptAES256(encrypted, decrypted);

            return Secret {std::move(decrypted)};
        }
        catch (const std::exception&)
        {
            // Deliberately not logging the exception text: it comes from the cipher layer
            // and there is no value in it here, while the surrounding message is the one
            // an operator can act on.
            logWarn("The credential stored for family '" + family +
                    "' could not be read. Continuing without a credential.");
            return std::nullopt;
        }
    }

    bool AgentCredentialStore::put(const std::string& family, const std::string& key, const Secret& value) const
    {
#ifdef WIN32
        // Refused rather than written unprotected. The module ships on Windows but its
        // registry support does not, and the only local protection this store has is the
        // file's permissions, which are not restricted on this platform. Writing a
        // credential that any local user can read would be worse than storing none.
        (void)family;
        (void)key;
        (void)value;
        logWarn("Storing a credential is not supported on Windows agents, so nothing was written.");
        return false;
#else
        nlohmann::json document;

        if (loadStore(m_path, document) == LoadOutcome::Unusable)
        {
            logWarn("The credential store at '" + m_path + "' could not be read, so it was not modified.");
            return false;
        }

        if (!document.is_object())
        {
            document = nlohmann::json::object();
        }

        std::error_code error;
        const auto directory {std::filesystem::path {m_path}.parent_path()};

        if (!directory.empty())
        {
            std::filesystem::create_directories(directory, error);

            if (error)
            {
                logWarn("Could not create the credential store directory '" + directory.string() + "'.");
                return false;
            }
        }

        std::vector<char> encrypted;

        try
        {
            EVPHelper<>().encryptAES256(value.value(), encrypted);
        }
        catch (const std::exception&)
        {
            logWarn("The credential for family '" + family + "' could not be stored.");
            return false;
        }

        if (!document[family].is_object())
        {
            document[family] = nlohmann::json::object();
        }

        document[family][key] = toHex(encrypted);

        // Written to a temporary file and renamed over the store, rather than truncating
        // the store and writing into it. Truncating first means a full disk, a signal or
        // a crash between the truncate and the write leaves no credentials at all, and
        // the caller is told the write failed while the damage is already done. A rename
        // within the same directory is atomic, so the store is either the old content or
        // the new one and never nothing.
        const auto temporaryPath {m_path + ".new"};

        {
            std::ofstream file {temporaryPath, std::ios::binary | std::ios::trunc};

            if (!file.is_open())
            {
                logWarn("Could not open the credential store at '" + m_path + "' for writing.");
                return false;
            }
        }

        // Restricted before the value is written into it, so the credential never exists
        // on disk under permissions wider than the final ones.
        const auto restricted {restrictPermissions(temporaryPath)};

        {
            std::ofstream file {temporaryPath, std::ios::binary | std::ios::trunc};

            if (!file.is_open())
            {
                logWarn("Could not open the credential store at '" + m_path + "' for writing.");
                return false;
            }

            file << document.dump(2);
            file.flush();

            if (!file.good())
            {
                file.close();
                std::filesystem::remove(temporaryPath, error);
                logWarn("Could not write the credential store at '" + m_path + "'.");
                return false;
            }
        }

        std::filesystem::rename(temporaryPath, m_path, error);

        if (error)
        {
            std::error_code ignored;
            std::filesystem::remove(temporaryPath, ignored);
            logWarn("Could not replace the credential store at '" + m_path + "'.");
            return false;
        }

        if (!restricted)
        {
            logWarn("The credential store at '" + m_path +
                    "' was written but its permissions could not be restricted. Restrict it so that only the "
                    "agent's own account can read it.");
        }

        return true;
#endif
    }

    bool AgentCredentialStore::remove(const std::string& family, const std::string& key) const
    {
        nlohmann::json document;

        if (loadStore(m_path, document) != LoadOutcome::Loaded)
        {
            return false;
        }

        const auto families {document.find(family)};

        if (families == document.end() || !families->is_object() || families->find(key) == families->end())
        {
            return false;
        }

        families->erase(key);

        if (families->empty())
        {
            document.erase(family);
        }

        const auto temporaryPath {m_path + ".new"};

        {
            std::ofstream file {temporaryPath, std::ios::binary | std::ios::trunc};

            if (!file.is_open())
            {
                logWarn("Could not open the credential store at '" + m_path + "' for writing.");
                return false;
            }

            restrictPermissions(temporaryPath);

            file << document.dump(2);
            file.flush();

            if (!file.good())
            {
                return false;
            }
        }

        std::error_code error;
        std::filesystem::rename(temporaryPath, m_path, error);

        return !error;
    }
} // namespace containerimages
