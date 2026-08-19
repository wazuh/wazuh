/*
 * Wazuh remoted module - agent enrollment authenticator
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "enrollmentAuthenticator.hpp"

#include "auth/cmac.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <memory>
#include <string>

namespace remoted::enrollment
{
    namespace
    {
        bool isAllDigits(std::string_view s)
        {
            return !s.empty() && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; });
        }

        bool isLowerHex32(std::string_view s)
        {
            if (s.size() != 32)
            {
                return false;
            }
            return std::all_of(
                s.begin(), s.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
        }

        struct ParsedWazuhEnroll
        {
            std::string_view timestamp;
            std::string_view mac;
        };

        // Parses "WazuhEnroll <timestamp>:<mac>" -- no agent-id field, unlike the "Wazuh
        // <agent-id>:<timestamp>:<mac>" scheme AuthMiddleware parses (see class comment).
        std::optional<ParsedWazuhEnroll> parseAuthorization(std::string_view header)
        {
            constexpr std::string_view kScheme = "WazuhEnroll ";
            if (header.size() <= kScheme.size() || header.substr(0, kScheme.size()) != kScheme)
            {
                return std::nullopt;
            }

            const std::string_view rest = header.substr(kScheme.size());
            const auto colon = rest.find(':');
            if (colon == std::string_view::npos)
            {
                return std::nullopt;
            }
            const std::string_view timestamp = rest.substr(0, colon);
            const std::string_view mac = rest.substr(colon + 1);

            if (!isAllDigits(timestamp))
            {
                return std::nullopt;
            }
            if (!isLowerHex32(mac))
            {
                return std::nullopt;
            }

            return ParsedWazuhEnroll {timestamp, mac};
        }

        std::string toUpper(std::string_view s)
        {
            std::string out(s);
            std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::toupper(c); });
            return out;
        }
    } // namespace

    EnrollmentAuthenticator::EnrollmentAuthenticator(EnrollmentAuthConfig config,
                                                     std::shared_ptr<remoted::auth::PasswordKeySource> keySource)
        : m_config(std::move(config))
        , m_keySource(std::move(keySource))
    {
    }

    std::optional<remoted::auth::AuthError>
    EnrollmentAuthenticator::authenticate(std::string_view authorizationHeader,
                                          std::string_view method,
                                          std::string_view requestTarget,
                                          std::string_view body,
                                          std::int64_t currentUnixTimeSeconds) const
    {
        if (!m_config.requirePassword)
        {
            return std::nullopt;
        }
        return authenticatePassword(authorizationHeader, method, requestTarget, body, currentUnixTimeSeconds);
    }

    std::optional<remoted::auth::AuthError>
    EnrollmentAuthenticator::authenticatePassword(std::string_view authorizationHeader,
                                                  std::string_view method,
                                                  std::string_view requestTarget,
                                                  std::string_view body,
                                                  std::int64_t currentUnixTimeSeconds) const
    {
        if (authorizationHeader.empty())
        {
            return remoted::auth::AuthError::MissingAuthorization;
        }

        const auto parsed = parseAuthorization(authorizationHeader);
        if (!parsed)
        {
            return remoted::auth::AuthError::MalformedAuthorization;
        }

        std::int64_t timestamp = 0;
        const auto [ptr, ec] =
            std::from_chars(parsed->timestamp.data(), parsed->timestamp.data() + parsed->timestamp.size(), timestamp);
        if (ec != std::errc {} || ptr != parsed->timestamp.data() + parsed->timestamp.size())
        {
            return remoted::auth::AuthError::MalformedAuthorization;
        }

        if (timestamp < currentUnixTimeSeconds - m_config.maxRequestAgeSeconds)
        {
            return remoted::auth::AuthError::ExpiredRequest;
        }
        if (timestamp > currentUnixTimeSeconds + m_config.maxFutureSkewSeconds)
        {
            return remoted::auth::AuthError::FutureRequest;
        }

        // Fail-closed: Password mode active but the key is unavailable (file missing/unreadable/
        // invalid, or not yet synced from the master to a worker) -- never fall back to Open mode.
        // See PasswordKeySource's class comment for why conflating the two would be a security bug.
        const auto key = m_keySource ? m_keySource->currentKey() : std::nullopt;
        if (!key)
        {
            return remoted::auth::AuthError::MissingKey;
        }

        std::array<std::uint8_t, remoted::auth::Cmac::kMacSize> expectedMac {};
        if (!remoted::auth::fromLowerHex(parsed->mac, expectedMac.data(), expectedMac.size()))
        {
            return remoted::auth::AuthError::MalformedAuthorization;
        }

        std::unique_ptr<remoted::auth::Cmac> cmac;
        try
        {
            // The key is always exactly 32 bytes (HKDF's fixed output length -- see
            // PasswordKeySource), so CmacKeyError cannot fire here; a CmacProviderError means
            // AES-CMAC itself is unavailable manager-wide, which collapses to the same
            // MissingKey/401 AuthMiddleware uses for that condition.
            cmac = std::make_unique<remoted::auth::Cmac>(*key);
        }
        catch (const std::exception&)
        {
            return remoted::auth::AuthError::MissingKey;
        }

        cmac->update("WAZUH-ENROLL\n");
        cmac->update("1\n");
        cmac->update(toUpper(method));
        cmac->update("\n");
        cmac->update(requestTarget);
        cmac->update("\n");
        cmac->update(parsed->timestamp);
        cmac->update("\n");
        cmac->update(body);

        const auto mac = cmac->finalize();
        if (!remoted::auth::constantTimeEquals(mac.data(), expectedMac.data(), mac.size()))
        {
            return remoted::auth::AuthError::InvalidMac;
        }

        return std::nullopt;
    }

} // namespace remoted::enrollment
