/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "authMiddleware.hpp"

#include <algorithm>
#include <charconv>

namespace remoted::auth
{

    const char* toString(AuthError err)
    {
        switch (err)
        {
            case AuthError::None: return "none";
            case AuthError::MissingProtocolVersion: return "missing_protocol_version";
            case AuthError::UnsupportedProtocolVersion: return "unsupported_protocol_version";
            case AuthError::MissingAuthorization: return "missing_authorization";
            case AuthError::MalformedAuthorization: return "malformed_authorization";
            case AuthError::UnknownAgent: return "unknown_agent";
            case AuthError::MissingKey: return "missing_key";
            case AuthError::ExpiredRequest: return "expired_request";
            case AuthError::FutureRequest: return "future_request";
            case AuthError::InvalidMac: return "invalid_mac";
            case AuthError::PayloadAgentMismatch: return "payload_agent_mismatch";
            case AuthError::BodyTooLarge: return "body_too_large";
        }
        return "unknown";
    }

    PublicError publicErrorFor(AuthError err)
    {
        switch (err)
        {
            case AuthError::MissingProtocolVersion: return {400, "Missing required header: protocol-version"};
            case AuthError::UnsupportedProtocolVersion: return {400, "Unsupported protocol-version"};
            case AuthError::PayloadAgentMismatch: return {400, "Invalid event batch"};
            case AuthError::BodyTooLarge: return {413, "Request payload is too large"};
            case AuthError::None: return {200, ""};
            // MissingAuthorization, MalformedAuthorization, UnknownAgent, MissingKey,
            // ExpiredRequest, FutureRequest, InvalidMac: collapse to one generic 401
            // so the client can never distinguish the reason.
            default: return {401, "Invalid client authentication"};
        }
    }

    namespace
    {

        bool isValidAgentIdChar(char c)
        {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                   c == '-';
        }

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

        struct ParsedAuthorization
        {
            std::string_view agentId;
            std::string_view timestamp;
            std::string_view mac;
        };

        // Parses "Wazuh <agent-id>:<timestamp>:<mac>" with no tolerance for extra
        // whitespace, extra delimiters, or a non-canonical scheme -- malformed
        // credentials must fail closed.
        std::optional<ParsedAuthorization> parseAuthorization(std::string_view header)
        {
            constexpr std::string_view kScheme = "Wazuh ";
            if (header.size() <= kScheme.size() || header.substr(0, kScheme.size()) != kScheme)
            {
                return std::nullopt;
            }

            std::string_view rest = header.substr(kScheme.size());

            const auto firstColon = rest.find(':');
            if (firstColon == std::string_view::npos)
            {
                return std::nullopt;
            }
            const std::string_view agentId = rest.substr(0, firstColon);
            rest.remove_prefix(firstColon + 1);

            const auto secondColon = rest.find(':');
            if (secondColon == std::string_view::npos)
            {
                return std::nullopt;
            }
            const std::string_view timestamp = rest.substr(0, secondColon);
            const std::string_view mac = rest.substr(secondColon + 1);

            if (agentId.empty() || !std::all_of(agentId.begin(), agentId.end(), isValidAgentIdChar))
            {
                return std::nullopt;
            }
            if (!isAllDigits(timestamp))
            {
                return std::nullopt;
            }
            if (!isLowerHex32(mac))
            {
                return std::nullopt;
            }
            // mac must not itself contain further ':' -- isLowerHex32 already
            // enforces an exact 32-char hex alphabet, so a stray delimiter would
            // already have been rejected.

            return ParsedAuthorization {agentId, timestamp, mac};
        }

        std::string toUpper(std::string_view s)
        {
            std::string out(s);
            std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::toupper(c); });
            return out;
        }

    } // namespace

    AuthMiddleware::AuthMiddleware(AuthConfig config, std::shared_ptr<IAgentKeystore> keystore)
        : m_config(std::move(config))
        , m_keystore(std::move(keystore))
    {
    }

    std::variant<AuthMiddleware::Session, AuthError>
    AuthMiddleware::beginSession(std::string_view protocolVersionHeader,
                                 std::string_view authorizationHeader,
                                 std::string_view method,
                                 std::string_view requestTarget,
                                 std::int64_t currentUnixTimeSeconds) const
    {
        // Step 1: protocol version. An empty value here must mean "absent or
        // duplicated" -- the transport collapses both cases before calling in,
        // since the header must be present exactly once.
        if (protocolVersionHeader.empty())
        {
            return AuthError::MissingProtocolVersion;
        }
        if (protocolVersionHeader != m_config.supportedProtocolVersion)
        {
            return AuthError::UnsupportedProtocolVersion;
        }

        // Step 2: parse Authorization.
        if (authorizationHeader.empty())
        {
            return AuthError::MissingAuthorization;
        }
        const auto parsed = parseAuthorization(authorizationHeader);
        if (!parsed)
        {
            return AuthError::MalformedAuthorization;
        }

        std::int64_t timestamp = 0;
        const auto [ptr, ec] =
            std::from_chars(parsed->timestamp.data(), parsed->timestamp.data() + parsed->timestamp.size(), timestamp);
        if (ec != std::errc {} || ptr != parsed->timestamp.data() + parsed->timestamp.size())
        {
            return AuthError::MalformedAuthorization;
        }

        // Step 3: timestamp window.
        if (timestamp < currentUnixTimeSeconds - m_config.maxRequestAgeSeconds)
        {
            return AuthError::ExpiredRequest;
        }
        if (timestamp > currentUnixTimeSeconds + m_config.maxFutureSkewSeconds)
        {
            return AuthError::FutureRequest;
        }

        // Step 4: look up the agent key.
        const std::string agentId(parsed->agentId);
        const auto agentKey = m_keystore->keyFor(agentId);
        if (!agentKey)
        {
            return AuthError::UnknownAgent;
        }
        if (agentKey->empty())
        {
            return AuthError::MissingKey;
        }

        // Step 5: initialize AES-CMAC with the canonical prefix. The timestamp
        // is re-used verbatim as the substring parsed from the header, not
        // reformatted from the integer, so agent and manager can never diverge
        // on padding/formatting.
        Session session;
        session.m_agentId = agentId;
        session.m_protocolVersion = std::string(protocolVersionHeader);
        session.m_method = toUpper(method);
        session.m_requestTarget = std::string(requestTarget);
        session.m_maxBodySize = m_config.maxBodySize;

        if (!fromLowerHex(parsed->mac, session.m_expectedMac.data(), session.m_expectedMac.size()))
        {
            return AuthError::MalformedAuthorization;
        }

        try
        {
            session.m_cmac = std::make_unique<Cmac>(*agentKey);
        }
        catch (const std::exception&)
        {
            return AuthError::MissingKey;
        }

        session.m_cmac->update("WAZUH-REQUEST\n");
        session.m_cmac->update(session.m_protocolVersion);
        session.m_cmac->update("\n");
        session.m_cmac->update(session.m_method);
        session.m_cmac->update("\n");
        session.m_cmac->update(session.m_requestTarget);
        session.m_cmac->update("\n");
        session.m_cmac->update(session.m_agentId);
        session.m_cmac->update("\n");
        session.m_cmac->update(parsed->timestamp);
        session.m_cmac->update("\n");

        return session;
    }

    AuthError AuthMiddleware::Session::update(const std::uint8_t* data, std::size_t len)
    {
        m_bodySizeSoFar += len;
        if (m_bodySizeSoFar > m_maxBodySize)
        {
            return AuthError::BodyTooLarge;
        }
        m_cmac->update(data, len);
        m_body.insert(m_body.end(), data, data + len);
        return AuthError::None;
    }

    std::variant<AuthenticatedRequest, AuthError> AuthMiddleware::Session::finish()
    {
        const auto mac = m_cmac->finalize();
        if (!constantTimeEquals(mac.data(), m_expectedMac.data(), mac.size()))
        {
            return AuthError::InvalidMac;
        }

        AuthenticatedRequest req;
        req.agentId = std::move(m_agentId);
        req.protocolVersion = std::move(m_protocolVersion);
        req.method = std::move(m_method);
        req.requestTarget = std::move(m_requestTarget);
        req.body = std::move(m_body);
        return req;
    }

} // namespace remoted::auth
