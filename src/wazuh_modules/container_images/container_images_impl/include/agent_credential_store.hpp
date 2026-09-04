/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AGENT_CREDENTIAL_STORE_HPP
#define _AGENT_CREDENTIAL_STORE_HPP

#include "credential_provider.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace containerimages
{
    /// @brief Default location of the store, relative to the agent installation.
    ///
    /// Not scoped to this module: the family argument is inherently multi-tenant, so a
    /// second module reading a credential later should not have to move the file. Only
    /// the `container_images` family is written today.
    constexpr auto CREDENTIAL_STORE_PATH {"queue/credentials/credentials.json"};

    /// @brief Family the container images module reads its credentials under.
    constexpr auto CREDENTIAL_FAMILY {"container_images"};

    /// @brief Largest store file that will be read.
    ///
    /// The document holds a handful of short strings. Anything past this is not a
    /// credential store, and reading it into memory is not something this module should
    /// be talked into by a file it does not own.
    constexpr std::uintmax_t MAX_CREDENTIAL_STORE_SIZE {1024 * 1024};

    /// @brief Credentials kept in a file next to the agent's other state.
    ///
    /// ## What this protects, and what it does not
    ///
    /// The value is kept out of `ossec.conf`, and therefore out of configuration
    /// backups, out of shared-configuration pushes and out of support bundles. That is
    /// the security property this store delivers, and it is the reason it exists.
    ///
    /// It is **not** encryption at rest. The stored bytes are produced by the same
    /// helper the manager keystore uses, which writes the key and the IV in front of the
    /// ciphertext, so anyone able to read the file can recover the value without holding
    /// any secret. The control that actually protects the value locally is the file's
    /// permissions. An attacker with agent-root reads it, exactly as they would read the
    /// manager keystore.
    ///
    /// This is stated here, rather than only in the documentation, so the next reader of
    /// this class cannot mistake the cipher for a guarantee.
    class AgentCredentialStore final : public ICredentialProvider
    {
        public:
            /// @param path Store location. Defaults to @ref CREDENTIAL_STORE_PATH.
            explicit AgentCredentialStore(std::string path = CREDENTIAL_STORE_PATH);

            /// @copydoc ICredentialProvider::get
            ///
            /// A store that does not exist, a family that is not in it and a key that is
            /// not in the family are all the same ordinary outcome: no credential, so the
            /// caller proceeds without one. Only a store that exists and cannot be read,
            /// parsed or decrypted is reported, once, naming the family and never the
            /// value.
            std::optional<Secret> get(const std::string& family, const std::string& key) const override;

            /// @brief Store @p value under @p family and @p key, replacing any previous one.
            ///
            /// Creates the store and its directory when they do not exist, and restricts
            /// the file's permissions before the value is written into it.
            ///
            /// @return True when the store was written.
            bool put(const std::string& family, const std::string& key, const Secret& value) const;

            /// @brief Remove a key, and the family once its last key is gone.
            /// @return True when the store was rewritten, false when the key was absent.
            bool remove(const std::string& family, const std::string& key) const;

            /// @brief The store's location.
            const std::string& path() const
            {
                return m_path;
            }

        private:
            std::string m_path;
    };
} // namespace containerimages

#endif // _AGENT_CREDENTIAL_STORE_HPP
