/*
 * Wazuh remoted module: signed WPK download identifiers
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "jwt/secureBytes.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace remoted::auth
{

    /// @brief Raw form of a task id: the 16 bytes behind its 8-4-4-4-12 lowercase hex text.
    using TaskIdBytes = std::array<std::uint8_t, 16>;

    /// @brief Parses an 8-4-4-4-12 lowercase hex task id (36 characters); nullopt for anything else.
    std::optional<TaskIdBytes> parseTaskId(std::string_view text);

    /// @brief Exact inverse of parseTaskId().
    std::string formatTaskId(const TaskIdBytes& taskId);

    /// @brief True when a /download resource id has the shape of an identifier ("wpk1." prefix and
    /// ".wpk" suffix, not overlapping). Shape only: says nothing about whether it verifies.
    bool looksLikeWpkId(std::string_view resourceId);

    /// @brief TTL to configure the codec with: the configured value, or 600 s when it is <= 0
    /// (remoted_module_config_t reads <= 0 as "module default").
    std::chrono::seconds effectiveWpkIdTtl(int configured);

    /**
     * @brief Issues and verifies the identifiers that stand in for a WPK file name in a
     *        remote_upgrade task.
     *
     * id = "wpk1." + base64url(S || tag) + ".wpk", with S = subject(4, BE) || exp(4, BE) ||
     * task_id(16) and tag = HMAC-SHA256(K, "WAZUH-WPK-ID\n1\n" || S)[:16]. K is derived from the
     * cluster key, which every node shares, so any node verifies what another issued. The id is
     * authenticated, not encrypted: none of its claims is secret.
     */
    class WpkIdCodec final
    {
    public:
        /// @brief nullopt when the key is not 32 characters of [A-Za-z0-9], ttl <= 0 or the
        /// derivation fails. Never throws.
        static std::optional<WpkIdCodec> fromClusterKey(std::string_view clusterKey, std::chrono::seconds ttl);

        /// @brief Identifier for @p subject and @p taskId expiring at now + ttl; nullopt when now is
        /// negative or the expiry does not fit 32 bits.
        std::optional<std::string> issue(std::uint32_t subject, const TaskIdBytes& taskId, std::int64_t now) const;

        /// @brief The task id when the tag verifies, the subject matches and 0 <= now < exp;
        /// nullopt otherwise, with no indication of which check failed.
        std::optional<TaskIdBytes> verify(std::string_view id, std::uint32_t subject, std::int64_t now) const;

    private:
        WpkIdCodec(jwt_profile::v1::SecureBytes key, std::chrono::seconds ttl);

        jwt_profile::v1::SecureBytes m_key;
        std::chrono::seconds m_ttl;
    };

    /// @brief What /control and /download need to issue and redeem identifiers. Each holder keeps
    /// its own reference to the codec, so it outlives whichever of them runs last.
    struct WpkIdHandling
    {
        std::shared_ptr<const WpkIdCodec> codec; ///< Empty: identifiers disabled.
        std::function<std::int64_t()> now;       ///< Empty: the wall clock.
    };

} // namespace remoted::auth
