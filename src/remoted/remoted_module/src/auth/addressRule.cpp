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

#include "addressRule.hpp"

#include <algorithm>
#include <charconv>
#include <string>

// Standalone Asio, for address parsing only. Kept out of addressRule.hpp so translation units that
// only need a Keystore do not pull it in.
#include <asio/ip/address.hpp>

namespace remoted::auth
{
    namespace
    {
        constexpr std::string_view kAnyLiteral {"any"};
        constexpr std::size_t kV4Bits {32};
        constexpr std::size_t kV6Bits {128};

        /// Parse a whole non-negative decimal field. Rejects a partial consume, so "24x" or "2 4"
        /// never reach the range check as 24.
        std::optional<unsigned int> parseWholeDecimal(std::string_view text)
        {
            unsigned int value {0};
            const auto* const end = text.data() + text.size();
            const auto [ptr, ec] = std::from_chars(text.data(), end, value);
            if (text.empty() || ec != std::errc {} || ptr != end)
            {
                return std::nullopt;
            }
            return value;
        }

        /// Parses an address, collapsing the v4-mapped form to plain IPv4 so that `::ffff:10.0.0.5`
        /// and `10.0.0.5` resolve to the same value. A trailing IPv6 zone id (`fe80::1%eth0`) is
        /// dropped: it names a local interface, not part of the address being compared, and a peer
        /// reported with one must still match an entry written without it.
        std::optional<asio::ip::address> parseAddress(std::string_view text)
        {
            const auto zone = text.find('%');
            if (zone != std::string_view::npos)
            {
                text = text.substr(0, zone);
            }

            asio::error_code ec;
            // make_address() takes a string, and the input is a view into a larger buffer.
            auto address = asio::ip::make_address(std::string {text}, ec);
            if (ec)
            {
                return std::nullopt;
            }
            if (address.is_v6() && address.to_v6().is_v4_mapped())
            {
                address = asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
            }
            return address;
        }

        /// Contiguous IPv4 mask for a prefix length. Shifting a 32-bit value by 32 is undefined, so
        /// /0 is answered directly.
        std::uint32_t v4MaskFromPrefix(unsigned int prefix)
        {
            return prefix == 0 ? 0u : (0xFFFFFFFFu << (kV4Bits - prefix));
        }

        /// Contiguous IPv6 mask for a prefix length: whole 0xFF bytes, then the partial byte.
        std::array<std::uint8_t, 16> v6MaskFromPrefix(unsigned int prefix)
        {
            std::array<std::uint8_t, 16> mask {};
            for (std::size_t i = 0; i < mask.size(); ++i)
            {
                const auto consumed = i * 8;
                if (prefix >= consumed + 8)
                {
                    mask[i] = 0xFF;
                }
                else if (prefix > consumed)
                {
                    mask[i] = static_cast<std::uint8_t>(0xFFu << (8 - (prefix - consumed)));
                }
                // else: past the prefix, stays 0.
            }
            return mask;
        }
    } // namespace

    std::optional<AddressRule> AddressRule::parse(std::string_view spec)
    {
        // A leading '!' is dropped and the remainder read positively, which is what the legacy keystore
        // does with the same column. Kept identical on purpose: a client.keys carried over from 4.x has
        // to authorize exactly the same agents it did there, so a line that worked before an upgrade
        // cannot start being rejected after it.
        if (!spec.empty() && spec.front() == '!')
        {
            spec.remove_prefix(1);
        }

        if (spec == kAnyLiteral)
        {
            return AddressRule {Any {}};
        }

        // Split on the single optional '/'. A second one makes the spec invalid.
        const auto slash = spec.find('/');
        const std::string_view addressText = spec.substr(0, slash);
        const bool hasSuffix = slash != std::string_view::npos;
        const std::string_view suffix = hasSuffix ? spec.substr(slash + 1) : std::string_view {};
        if (hasSuffix && suffix.find('/') != std::string_view::npos)
        {
            return std::nullopt;
        }

        const auto address = parseAddress(addressText);
        if (!address)
        {
            return std::nullopt;
        }

        if (address->is_v4())
        {
            std::uint32_t mask {0xFFFFFFFFu};
            if (hasSuffix)
            {
                // Length tells the two apart unambiguously: a CIDR is at most "32", and the shortest
                // dotted mask is "0.0.0.0".
                if (suffix.size() <= 2)
                {
                    const auto prefix = parseWholeDecimal(suffix);
                    if (!prefix || *prefix > kV4Bits)
                    {
                        return std::nullopt;
                    }
                    mask = v4MaskFromPrefix(*prefix);
                }
                else
                {
                    // Used verbatim, with no contiguity check: a mask such as 255.0.255.0 is accepted
                    // and applied as written.
                    const auto dotted = parseAddress(suffix);
                    if (!dotted || !dotted->is_v4())
                    {
                        return std::nullopt;
                    }
                    mask = dotted->to_v4().to_uint();
                }
            }

            return AddressRule {V4 {address->to_v4().to_uint() & mask, mask}};
        }

        // IPv6: prefix only, no dotted mask.
        auto prefix = static_cast<unsigned int>(kV6Bits);
        if (hasSuffix)
        {
            const auto parsed = parseWholeDecimal(suffix);
            if (!parsed || *parsed > kV6Bits)
            {
                return std::nullopt;
            }
            prefix = *parsed;
        }

        const auto mask = v6MaskFromPrefix(prefix);
        auto bytes = address->to_v6().to_bytes();
        std::array<std::uint8_t, 16> masked {};
        for (std::size_t i = 0; i < masked.size(); ++i)
        {
            masked[i] = static_cast<std::uint8_t>(bytes[i] & mask[i]);
        }

        return AddressRule {V6 {masked, mask}};
    }

    bool AddressRule::matches(std::string_view peerIp) const
    {
        // Answered before parsing the peer, so an unparseable address cannot turn `any` into a
        // rejection.
        if (std::holds_alternative<Any>(m_rule))
        {
            return true;
        }

        const auto peer = parseAddress(peerIp);
        if (!peer)
        {
            return false;
        }

        if (const auto* v4 = std::get_if<V4>(&m_rule))
        {
            return peer->is_v4() && (peer->to_v4().to_uint() & v4->mask) == v4->address;
        }

        const auto& v6 = std::get<V6>(m_rule);
        if (!peer->is_v6())
        {
            return false;
        }
        const auto bytes = peer->to_v6().to_bytes();
        for (std::size_t i = 0; i < v6.mask.size(); ++i)
        {
            if (static_cast<std::uint8_t>(bytes[i] & v6.mask[i]) != v6.address[i])
            {
                return false;
            }
        }
        return true;
    }

} // namespace remoted::auth
