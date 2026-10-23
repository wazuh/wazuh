/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_CONFIG_HPP
#define _CONTAINER_IMAGES_CONFIG_HPP

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief The kinds of image source the configuration grammar accepts.
    ///
    /// The three entry types are fixed here so that adding a source later adds behaviour
    /// only: the configuration does not change again. Only Archive is implemented at this
    /// stage; the other two are accepted and reported as unimplemented.
    enum class ReferenceType
    {
        Registry,   ///< `<ref>`: an image in a remote registry.
        Archive,    ///< `<archive>`: a saved image archive or an OCI image layout on disk.
        EngineStore ///< `<local>`: an image in the local container engine store.
    };

    /// @brief One configured image source.
    struct ConfiguredReference
    {
        ReferenceType type {ReferenceType::Archive};
        std::string location; ///< Path or image reference, as written in the configuration.
    };

    /// @brief Configuration name of a reference type, also stored as the reference type of
    /// every inventoried row.
    inline std::string referenceTypeName(const ReferenceType type)
    {
        switch (type)
        {
            case ReferenceType::Registry: return "ref";
            case ReferenceType::Archive: return "archive";
            case ReferenceType::EngineStore: return "local";
            default: return "unknown";
        }
    }

    /// @brief Resolve a configuration entry name to its reference type.
    /// @return True when @p name is one of the accepted entry types.
    inline bool parseReferenceType(const std::string& name, ReferenceType& type)
    {
        if (name == "ref")
        {
            type = ReferenceType::Registry;
        }
        else if (name == "archive")
        {
            type = ReferenceType::Archive;
        }
        else if (name == "local")
        {
            type = ReferenceType::EngineStore;
        }
        else
        {
            return false;
        }

        return true;
    }

    /// @brief Credentials for one registry, named by keystore key rather than by value.
    ///
    /// The configuration holds key names only, so no credential is ever written into
    /// `ossec.conf`. A reference whose registry has no entry here is attempted with no
    /// credential at all, which is what a public repository needs.
    struct RegistryCredentials
    {
        std::string host;         ///< Registry host this applies to, e.g. "ghcr.io".
        std::string userKey;      ///< Keystore key holding the user name.
        std::string passkeyKey;   ///< Keystore key holding the access token.
    };

    /// @brief Ceiling on the decompressed bytes read out of one layer blob.
    ///
    /// LayerReader walks the full decompressed content of a layer, including the entries it
    /// skips, so an attacker-controlled compression ratio otherwise bounds nothing: a few MiB
    /// of gzip can expand past what the module could ever need to read in looking for a
    /// package database. 8 GiB is comfortably above a real single-layer uncompressed size
    /// while keeping the worst case bounded to a few seconds instead of hours.
    constexpr std::uint64_t MAX_LAYER_DECOMPRESSED_SIZE {8ULL * 1024 * 1024 * 1024};

    /// @brief Bounds on what one scan may spend on remote references.
    struct RegistryLimits
    {
        /// Ceiling on the compressed bytes retrieved for a single image.
        std::uint64_t maxImageBytes {2ULL * 1024 * 1024 * 1024};

        /// Ceiling on the compressed bytes retrieved across a whole scan. A scan that
        /// reaches it stops starting new references rather than being cut off mid-image,
        /// so what it has already read stays usable.
        std::uint64_t maxScanBytes {8ULL * 1024 * 1024 * 1024};

        /// Ceiling on the decompressed bytes of one layer. A layer that expands past it
        /// fails the reference, since what lies beyond cannot be read. Not configurable:
        /// a field only so that a test can lower it.
        std::uint64_t maxLayerDecompressedBytes {MAX_LAYER_DECOMPRESSED_SIZE};

        long connectTimeoutMs {10000};  ///< Ceiling on establishing one connection.
        long requestTimeoutMs {30000};  ///< Ceiling on one metadata request, and the
                                        ///< stall window for a blob transfer.

        /// Ceiling on how long a layer transfer may go without delivering a byte.
        ///
        /// Not a ceiling on the whole transfer: a blob is suspended whenever the caller
        /// is slower than the network, so libcurl's total timeout would abort a healthy
        /// read of a large layer. The wait restarts whenever bytes arrive and does not
        /// run while the transfer is suspended. libcurl's stall detector, which fires
        /// below 1 KiB/s over @ref requestTimeoutMs, normally ends a stalled transfer
        /// first; this is the backstop.
        long blobIdleTimeoutMs {300000};
        int maxAttempts {4};            ///< Attempts per request, including the first.

        /// Wait before the second attempt, doubling thereafter. Configurable so a test
        /// does not have to spend the real back-off to exercise the retry path.
        long retryBaseDelayMs {1000};
    };

    /// @brief Internal configuration model for the module.
    struct ContainerImagesConfig
    {
        bool enabled {true};
        bool scanOnStart {true};
        unsigned int interval {3600};                   ///< Seconds between scans.
        std::vector<ConfiguredReference> references;    ///< The configured image sources.

        // Remote registries.
        std::vector<RegistryCredentials> registryAuth;  ///< Per-registry credential key names.
        std::string caBundle;                           ///< Certificate bundle. Detected when empty.
        RegistryLimits limits;

        // Persistence.
        std::string dbPath {"queue/container_images/db/container_images.db"}; ///< Local inventory DB.

        /// @brief The credential entry for a registry host, or nothing when it has none.
        ///
        /// Host names are not case sensitive. The parser already lowercases what it reads, so
        /// this is the second line of defence for an entry that reached the model another way.
        const RegistryCredentials* credentialsFor(const std::string& host) const
        {
            const auto sameCharacter = [](const char left, const char right)
            {
                return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
            };

            for (const auto& entry : registryAuth)
            {
                if (entry.host.size() == host.size() && std::equal(host.begin(), host.end(), entry.host.begin(), sameCharacter))
                {
                    return &entry;
                }
            }

            return nullptr;
        }
    };
} // namespace containerimages

#endif // _CONTAINER_IMAGES_CONFIG_HPP
