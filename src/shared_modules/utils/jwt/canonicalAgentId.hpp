/*
 * Wazuh shared modules utils - JWT agent authentication profile
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/// @file canonicalAgentId.hpp
/// The agent identity as the profile sees it: a numeric id (authd assigns them sequentially) whose
/// canonical text is zero-padded to at least three digits ("001"), the same form remoted's keystore,
/// the API and the indexer documents use. `kid`, `sub` and the `iss` suffix must all carry exactly
/// this text. The input is never interpreted as a path, URL or anything but ASCII digits.

#pragma once

#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

namespace jwt_profile::v1
{
    class CanonicalAgentId final
    {
    public:
        using Numeric = std::uint32_t;

        /// Minimum width of the canonical text ("1" -> "001"); wider ids keep their digits.
        static constexpr std::size_t kMinWidth = 3;
        /// Longest digit string a Numeric can hold (4294967295); anything longer is rejected before
        /// parsing, which also bounds the work done on hostile input.
        static constexpr std::size_t kMaxDigits = 10;

        /// @brief Lenient parse: ASCII digits only, must fit a Numeric; leading zeros are accepted and
        /// normalised ("0001" -> "001"). For configuration values (the agent's own id).
        static std::optional<CanonicalAgentId> parse(std::string_view text) noexcept
        {
            if (text.empty() || text.size() > kMaxDigits || !allDigits(text))
            {
                return std::nullopt;
            }
            Numeric value = 0;
            const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
            if (ec != std::errc {} || ptr != text.data() + text.size())
            {
                return std::nullopt;
            }
            return CanonicalAgentId {value};
        }

        /// @brief Strict parse: the text must already be the canonical form. For values read from a
        /// token (`kid`, `sub`), where a non-canonical spelling is a protocol violation.
        static std::optional<CanonicalAgentId> parseCanonical(std::string_view text) noexcept
        {
            auto parsed = parse(text);
            if (!parsed || parsed->text() != text)
            {
                return std::nullopt;
            }
            return parsed;
        }

        static CanonicalAgentId fromNumeric(Numeric value) noexcept
        {
            return CanonicalAgentId {value};
        }

        const std::string& text() const noexcept
        {
            return m_text;
        }
        Numeric numeric() const noexcept
        {
            return m_numeric;
        }

        friend bool operator==(const CanonicalAgentId& a, const CanonicalAgentId& b) noexcept
        {
            return a.m_numeric == b.m_numeric;
        }
        friend bool operator!=(const CanonicalAgentId& a, const CanonicalAgentId& b) noexcept
        {
            return !(a == b);
        }

    private:
        explicit CanonicalAgentId(Numeric value)
            : m_numeric(value)
            , m_text(std::to_string(value))
        {
            if (m_text.size() < kMinWidth)
            {
                m_text.insert(0, kMinWidth - m_text.size(), '0');
            }
        }

        static bool allDigits(std::string_view text) noexcept
        {
            for (const char c : text)
            {
                if (c < '0' || c > '9')
                {
                    return false;
                }
            }
            return true;
        }

        Numeric m_numeric;
        std::string m_text;
    };
} // namespace jwt_profile::v1
