/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * August 18, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <variant>

namespace remoted::auth
{

    /**
     * @brief The address restriction spelled by one client.keys `ip` column.
     *
     * Enforces the same restriction the legacy remoted applies (OS_IsValidIP() + OS_IPFound() in
     * shared/src/validate_op.c), so one client.keys authorizes the same peers on both pipelines: an
     * agent registered with a fixed address or a range may only connect from it, and `any` accepts
     * every peer.
     */
    class AddressRule
    {
    public:
        /**
         * @brief Parse one client.keys `ip` column.
         *
         * Accepted forms:
         *  - `any` (case-sensitive) -- matches every peer, in both families.
         *  - an IPv4 address, alone (an implicit /32), with `/CIDR` (0-32), or with a dotted `/mask`.
         *    A dotted mask is not required to be contiguous.
         *  - an IPv6 address, alone (an implicit /128) or with `/prefix` (0-128). Dotted masks are
         *    IPv4-only.
         *  - an `::ffff:a.b.c.d` v4-mapped form, unmapped to plain IPv4 before use, so it compares
         *    equal to the same address observed as plain IPv4.
         *
         * A leading `!` is stripped and the remainder read as an ordinary positive rule -- it is not a
         * negation. That mirrors the legacy keystore, where `OS_IsValidIP()` drops the `!` before
         * storing the text so `OS_IPFound()`'s negation branch can never fire, and it is deliberate: a
         * `client.keys` migrated from 4.x must authorize the same agents it authorized there.
         *
         * @param spec The column text, exactly as read from the file.
         * @return The parsed rule, or std::nullopt if the text is not a valid address spec.
         *         std::nullopt means *unusable line*, never "no restriction" -- `any` is a rule.
         */
        static std::optional<AddressRule> parse(std::string_view spec);

        /**
         * @brief Whether a peer address satisfies this rule.
         *
         * @param peerIp Textual peer address, as observed on the socket.
         * @return true if the peer is allowed. false for a peer of the other family (unless this rule
         *         is `any`), and false for text that is not a valid address.
         */
        bool matches(std::string_view peerIp) const;

    private:
        /// Accepts every peer, in either family.
        struct Any
        {
        };

        /// Host byte order; `address` is pre-masked at parse time.
        struct V4
        {
            std::uint32_t address {};
            std::uint32_t mask {};
        };

        /// Bytes as the address is written; `address` pre-masked at parse time.
        struct V6
        {
            std::array<std::uint8_t, 16> address {};
            std::array<std::uint8_t, 16> mask {};
        };

        // No default constructor: every rule comes from parse(), so no code path can leave a
        // permissive (Any) rule behind by forgetting an assignment.
        explicit AddressRule(std::variant<Any, V4, V6> rule)
            : m_rule {std::move(rule)}
        {
        }

        std::variant<Any, V4, V6> m_rule;
    };

} // namespace remoted::auth
