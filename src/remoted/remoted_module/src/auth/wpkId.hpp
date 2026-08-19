/*
 * Wazuh remoted module - signed WPK identifiers (PoC for #38283)
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

namespace remoted::auth
{

    /// What a signed identifier asserts. No filename: the package is found from the task id, so
    /// there is nothing here worth hiding and the identifier is authenticated, not encrypted.
    struct WpkIdClaims
    {
        std::uint32_t subject {0};              ///< Agent id it was issued to.
        std::uint32_t expiresAt {0};            ///< Wall-clock seconds, compared against the local clock.
        std::array<std::uint8_t, 16> taskId {}; ///< Raw task_id digest; names the package on disk.
    };

    /**
     * @brief Shaped so the filename grammar the manager already has accepts it.
     *
     * `wpk1.<base64url>.wpk` satisfies isValidWpkFilename() as written -- the charset is a subset of
     * `[A-Za-z0-9._-]`, it does not start with a dot, it ends in `.wpk`. That is the whole trick: no
     * new parser on the manager, and no change at all on a deployed agent, which simply treats it as
     * an opaque package name for both the request and its staging path.
     */
    constexpr std::string_view kIdPrefix {"wpk1."};
    constexpr std::string_view kIdSuffix {".wpk"};

    /// subject(4) + exp(4) + task_id(16), then a 16-byte truncated HMAC over them.
    constexpr std::size_t kClaimBytes {24};
    constexpr std::size_t kTagBytes {16};

    /// How long an identifier stays usable. UNMEASURED placeholder -- it must be derived from real
    /// transfer time against the retry budget before this ships.
    constexpr std::uint32_t kIdTtlSeconds {900};

    /// @brief Cheap pre-filter on the shape. A real package can be named this way, so verification
    ///        is what actually decides.
    bool looksLikeSignedId(std::string_view value);

    /// @brief Render 16 raw digest bytes as the UUID-shaped task id the task manager prints.
    std::string taskIdToString(const std::array<std::uint8_t, 16>& raw);

    /**
     * @brief The manager-side key, derived from `<cluster><key>`.
     *
     * Already distributed to every node, so there is no new file, no sync entry and no waiting on
     * the master. HKDF gives this use its own key, so it never shares material with the cluster
     * protocol itself.
     *
     * Refuses the default published in the installation guide: a key any reader can reproduce is no
     * key, and signing under it would be theatre. Unusable means the manager sends real filenames.
     *
     * Re-read while running, because the configuration can change under a live manager.
     */
    class WpkIdKey
    {
    public:
        static constexpr const char* kDefaultConfigPath = "etc/wazuh-manager.conf";
        static constexpr const char* kRefusedClusterKey = "fd3350b86d239654e34866ab3c4988a8";
        static constexpr int kRecheckIntervalSeconds = 10;

        explicit WpkIdKey(std::string configPath = kDefaultConfigPath,
                          int recheckIntervalSeconds = kRecheckIntervalSeconds);

        bool usable() const;

        /// @return `wpk1.<base64url>.wpk`, or empty when unusable.
        std::string sign(const WpkIdClaims& claims) const;

        /**
         * @brief Verify @p value, then check it against the caller and the clock.
         *
         * @param authenticatedAgent Agent id the auth middleware resolved, never the body's.
         * @return true only if the tag verifies, the subject matches and the expiry has not passed.
         */
        bool verify(std::string_view value,
                    std::uint32_t authenticatedAgent,
                    std::uint64_t now,
                    WpkIdClaims& out) const;

    private:
        struct Fingerprint
        {
            bool present {false};
            std::uint64_t dev {0}, ino {0}, size {0};
            std::int64_t mtimeSec {0}, mtimeNsec {0};
            bool operator==(const Fingerprint& o) const noexcept;
        };

        void refreshLocked() const;

        std::string m_configPath;
        int m_recheckIntervalSeconds;

        mutable std::mutex m_mutex;
        mutable std::array<std::uint8_t, 32> m_key {};
        mutable bool m_usable {false};
        mutable Fingerprint m_fingerprint;
        mutable std::int64_t m_lastCheckMonotonicSec {0};
        mutable bool m_everChecked {false};
    };

    /// Process-wide key, loaded on first use. A real implementation injects this.
    const WpkIdKey& wpkIdKey();

} // namespace remoted::auth
