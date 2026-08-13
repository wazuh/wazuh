/*
 * Wazuh remoted module - Hash cache
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "hashCache.hpp"
#include "json.hpp"
#include "mergedMgWatcher.hpp"
#include <array>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <openssl/evp.h>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace remoted::control
{
    namespace
    {
        constexpr std::array<char, 16> kHexDigits {
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        // A group name is safe iff it matches [A-Za-z0-9._-]+ and is not "." or "..".
        // This mirrors what the framework enforces on group creation.
        bool isSafeGroupToken(std::string_view token)
        {
            if (token.empty() || token == "." || token == "..")
            {
                return false;
            }
            for (unsigned char c : token)
            {
                const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                c == '.' || c == '_' || c == '-';
                if (!ok)
                {
                    return false;
                }
            }
            return true;
        }

        std::string toHex(const unsigned char* bytes, size_t len)
        {
            std::string out;
            out.resize(len * 2);
            for (size_t i = 0; i < len; ++i)
            {
                out[2 * i] = kHexDigits[(bytes[i] >> 4) & 0x0F];
                out[2 * i + 1] = kHexDigits[bytes[i] & 0x0F];
            }
            return out;
        }
    } // namespace

    class EVPContext
    {
    public:
        EVPContext()
            : m_ctx(EVP_MD_CTX_new())
        {
        }
        ~EVPContext()
        {
            if (m_ctx)
                EVP_MD_CTX_free(m_ctx);
        }

        operator EVP_MD_CTX*()
        {
            return m_ctx;
        }
        bool valid() const
        {
            return m_ctx != nullptr;
        }

        EVPContext(const EVPContext&) = delete;
        EVPContext& operator=(const EVPContext&) = delete;

    private:
        EVP_MD_CTX* m_ctx;
    };

    class HashCache::Impl
    {
    public:
        explicit Impl(const Config& config)
            : m_config(config)
            , m_settingsHashComputed(false)
        {
            m_watcher = std::make_unique<MergedMgWatcher>(m_config.sharedGroupsRoot,
                                                          m_config.multiGroupsRoot,
                                                          [this](const std::string& mergedMgPath)
                                                          { invalidateConfigHash(mergedMgPath); });
        }

        ~Impl()
        {
            stop();
        }

        void stop()
        {
            if (m_watcher)
            {
                m_watcher->stop();
            }
        }

        std::string getMergedMgPath(const std::string& groupsCsv) const
        {
            if (groupsCsv.empty())
            {
                return {};
            }

            // Single group: <sharedGroupsRoot>/<group>/merged.mg.
            if (groupsCsv.find(',') == std::string::npos)
            {
                if (!isSafeGroupToken(groupsCsv))
                {
                    return {};
                }
                return m_config.sharedGroupsRoot + "/" + groupsCsv + "/merged.mg";
            }

            // Multigroup: <multiGroupsRoot>/<sha256(csv)[:8]>/merged.mg.
            // Every token must be safe; the CSV must not contain "..".
            size_t start = 0;
            while (start < groupsCsv.size())
            {
                size_t comma = groupsCsv.find(',', start);
                size_t end = (comma == std::string::npos) ? groupsCsv.size() : comma;
                if (!isSafeGroupToken(std::string_view(groupsCsv).substr(start, end - start)))
                {
                    return {};
                }
                if (comma == std::string::npos)
                    break;
                start = comma + 1;
            }

            std::string hash = sha256Hex(groupsCsv);
            if (hash.size() < 8)
            {
                return {};
            }
            return m_config.multiGroupsRoot + "/" + hash.substr(0, 8) + "/merged.mg";
        }

        std::string getSettingsHash()
        {
            {
                std::shared_lock lock(m_settingsMutex);
                if (m_settingsHashComputed)
                {
                    return m_settingsHash;
                }
            }

            nlohmann::json envelope;
            envelope["limits"] = m_config.limits;
            envelope["cluster"]["name"] = m_config.clusterName;

            std::string hash = sha256Hex(envelope.dump());
            // Do not cache a failed hash: an OpenSSL transient error would
            // otherwise pin an empty settings_hash for the whole process life.
            if (hash.empty())
            {
                return hash;
            }

            std::unique_lock writeLock(m_settingsMutex);
            if (!m_settingsHashComputed)
            {
                m_settingsHash = std::move(hash);
                m_settingsHashComputed = true;
            }
            return m_settingsHash;
        }

        std::string getConfigHash(const std::string& mergedMgPath)
        {
            if (mergedMgPath.empty())
            {
                return {};
            }

            {
                std::shared_lock lock(m_configMutex);
                auto it = m_configCache.find(mergedMgPath);
                if (it != m_configCache.end())
                {
                    return it->second;
                }
            }

            std::string hash = sha256File(mergedMgPath);
            // Do not cache transient I/O errors: an empty entry would be served
            // on every subsequent notify until the watcher invalidates it, and
            // if the failure wasn't a real file change the watcher never fires.
            if (hash.empty())
            {
                return hash;
            }

            std::unique_lock lock(m_configMutex);
            m_configCache[mergedMgPath] = hash;
            return hash;
        }

        void invalidateConfigHash(const std::string& mergedMgPath)
        {
            if (mergedMgPath.empty())
            {
                return;
            }
            std::unique_lock lock(m_configMutex);
            m_configCache.erase(mergedMgPath);
        }

    private:
        static std::string sha256Hex(std::string_view data)
        {
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hashLen = 0;

            EVPContext ctx;
            if (!ctx.valid())
                return {};

            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
                EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 || EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1)
            {
                return {};
            }
            return toHex(hash, hashLen);
        }

        static std::string sha256File(const std::string& filePath)
        {
            std::ifstream file(filePath, std::ios::binary);
            if (!file)
            {
                return {};
            }

            EVPContext ctx;
            if (!ctx.valid())
                return {};

            if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1)
            {
                return {};
            }

            char buffer[kFileHashBufferSize];
            while (file.good())
            {
                file.read(buffer, sizeof(buffer));
                const auto n = file.gcount();
                if (n > 0 && EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(n)) != 1)
                {
                    return {};
                }
            }
            // Reject any real I/O error (badbit). eofbit alone is expected and OK.
            if (file.bad())
            {
                return {};
            }

            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hashLen = 0;
            if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1)
            {
                return {};
            }
            return toHex(hash, hashLen);
        }

        Config m_config;
        std::unique_ptr<MergedMgWatcher> m_watcher;

        // Settings hash: computed once and cached forever.
        std::shared_mutex m_settingsMutex;
        std::string m_settingsHash;
        bool m_settingsHashComputed;

        // Config hash: keyed by resolved merged.mg absolute path, so the watcher's
        // invalidation path matches the read path (no CSV<->folder-hash mismatch).
        std::shared_mutex m_configMutex;
        std::unordered_map<std::string, std::string> m_configCache;
    };

    HashCache::HashCache(const Config& config)
        : m_impl(std::make_unique<Impl>(config))
    {
    }

    HashCache::~HashCache() = default;

    std::string HashCache::getMergedMgPath(const std::string& groupsCsv) const
    {
        return m_impl->getMergedMgPath(groupsCsv);
    }

    std::string HashCache::getSettingsHash()
    {
        return m_impl->getSettingsHash();
    }

    std::string HashCache::getConfigHash(const std::string& mergedMgPath)
    {
        return m_impl->getConfigHash(mergedMgPath);
    }

    void HashCache::invalidateConfigHash(const std::string& mergedMgPath)
    {
        m_impl->invalidateConfigHash(mergedMgPath);
    }

    void HashCache::stop()
    {
        m_impl->stop();
    }

} // namespace remoted::control
