/*
 * Wazuh Module for Container Images
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_TOKEN_CACHE_HPP
#define _REGISTRY_TOKEN_CACHE_HPP

#include "credential_provider.hpp"

#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace containerimages
{
    /// @brief Registry access tokens that outlive one reference.
    ///
    /// A private ECR token is obtained with a signed call to AWS and is good for hours,
    /// while a reader lives for one reference. Held here, owned by the module rather than
    /// by a reader, the token obtained for one reference serves every other reference of
    /// the same registry and credential until it is about to expire.
    ///
    /// Only successes are stored. A failure is never remembered, so a credential that was
    /// wrong and has since been corrected works at the next attempt.
    class RegistryTokenCache final
    {
        public:
            using Clock = std::function<std::chrono::system_clock::time_point()>;

            /// @param clock  Source of the current time, replaceable so expiry is testable
            ///               without waiting for it.
            /// @param margin How long before its expiry a token stops being served, so a
            ///               token is not handed out that dies mid-image.
            explicit RegistryTokenCache(Clock clock = [] { return std::chrono::system_clock::now(); },
                                        std::chrono::seconds margin = std::chrono::minutes {10})
                : m_clock {std::move(clock)}
                , m_margin {margin}
            {
            }

            /// @brief The key for a token: the registry, the credential's key names and the
            /// region it was issued for. Key names, never values.
            static std::string makeKey(const std::string& host,
                                       const std::string& accessKeyIdKey,
                                       const std::string& secretAccessKeyKey,
                                       const std::string& region)
            {
                return host + '\n' + accessKeyIdKey + '\n' + secretAccessKeyKey + '\n' + region;
            }

            /// @brief A copy of the token for @p key, when one is stored and still valid.
            std::optional<Secret> lookup(const std::string& key)
            {
                std::lock_guard<std::mutex> lock {m_mutex};

                const auto entry {m_entries.find(key)};

                if (entry == m_entries.end())
                {
                    return std::nullopt;
                }

                if (m_clock() + m_margin >= entry->second.expiresAt)
                {
                    m_entries.erase(entry);
                    return std::nullopt;
                }

                return Secret {entry->second.token.value()};
            }

            void store(const std::string& key, Secret token, const std::chrono::system_clock::time_point expiresAt)
            {
                std::lock_guard<std::mutex> lock {m_mutex};

                m_entries[key] = Entry {std::move(token), expiresAt};
            }

            /// @brief Drop the token for @p key, because the registry refused it.
            void invalidate(const std::string& key)
            {
                std::lock_guard<std::mutex> lock {m_mutex};

                m_entries.erase(key);
            }

            void clear()
            {
                std::lock_guard<std::mutex> lock {m_mutex};

                m_entries.clear();
            }

            std::size_t size() const
            {
                std::lock_guard<std::mutex> lock {m_mutex};

                return m_entries.size();
            }

        private:
            struct Entry
            {
                Secret token;
                std::chrono::system_clock::time_point expiresAt;
            };

            Clock m_clock;
            std::chrono::seconds m_margin;
            mutable std::mutex m_mutex;
            std::map<std::string, Entry> m_entries;
    };
} // namespace containerimages

#endif // _REGISTRY_TOKEN_CACHE_HPP
