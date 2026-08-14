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

#include "common/logThrottle.hpp"
#include "loggerHelper.h"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <string>

namespace remoted::auth
{
    namespace
    {
        constexpr auto AUTH_MIDDLEWARE_LOGTAG {"wazuh-manager-remoted:auth"};

        // Function-local statics rather than members: loggerHelper.h must stay out of
        // authMiddleware.hpp (the tests include it, and Log::GLOBAL_LOG_FUNCTION is DSO-hidden),
        // and both of these are process-wide conditions anyway.
        const LogFn& logFn()
        {
            static const LogFn instance {AUTH_MIDDLEWARE_LOGTAG};
            return instance;
        }

        // A broken crypto provider fails EVERY request, so this would otherwise emit one ERROR per
        // request for as long as the condition lasts.
        remoted::common::LogThrottle& cmacUnavailableThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }
    } // namespace

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
            case AuthError::UnsupportedContentEncoding: return "unsupported_content_encoding";
            case AuthError::MalformedContentEncoding: return "malformed_content_encoding";
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
            case AuthError::MalformedContentEncoding: return {400, "Malformed compressed body"};
            case AuthError::UnsupportedContentEncoding: return {415, "Unsupported Content-Encoding"};
            case AuthError::None: return {200, ""};
            // MissingAuthorization, MalformedAuthorization, UnknownAgent, MissingKey,
            // ExpiredRequest, FutureRequest, InvalidMac: collapse to one generic 401
            // so the client can never distinguish the reason.
            default: return {401, "Invalid client authentication"};
        }
    }

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

        /**
         * @brief The agent id as client.keys spells it: decimal, zero-padded to three digits.
         *
         * authd assigns ids in this form and every reader matches on it -- the API's agent list, and
         * the document id `POST /stats` writes into `wazuh-agent-stats`. Derived from the numeric id
         * rather than from the header text, because the header text is not canonical: the key lookup
         * resolves numerically, so an agent signing "1" instead of "001" authenticates fine and would
         * otherwise reach the endpoints as a second, unmatchable identity.
         */
        std::string canonicalAgentId(AgentId numericId)
        {
            constexpr std::size_t kMinWidth {3};
            auto text = std::to_string(numericId);
            return text.size() >= kMinWidth ? text : std::string(kMinWidth - text.size(), '0').append(text);
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

            // An agent id is always numeric by design -- reject anything else here, rather than
            // letting it reach the (numeric) Keystore lookup.
            if (!isAllDigits(agentId))
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

        // Step 4: look up the agent key. parseAuthorization() already guarantees parsed->agentId is
        // all-digits and non-empty (isAllDigits()), so from_chars can only fail here on overflow
        // (more digits than AgentId holds) -- no real agent has an id that large, so treat it the
        // same as unknown.
        const std::string agentId(parsed->agentId);
        AgentId numericAgentId = 0;
        const auto [agentIdEnd, agentIdEc] =
            std::from_chars(parsed->agentId.data(), parsed->agentId.data() + parsed->agentId.size(), numericAgentId);
        if (agentIdEc != std::errc {} || agentIdEnd != parsed->agentId.data() + parsed->agentId.size())
        {
            return AuthError::UnknownAgent;
        }
        const auto agentKey = m_keystore->keyFor(numericAgentId);
        if (!agentKey)
        {
            return AuthError::UnknownAgent;
        }
        if (agentKey->empty())
        {
            return AuthError::MissingKey;
        }

        // Step 5: initialize AES-CMAC with the canonical prefix. The timestamp and the agent id are
        // re-used verbatim as the substrings parsed from the header, not reformatted from their
        // integers, so agent and manager can never diverge on padding/formatting. The id the request
        // CARRIES onwards is canonicalized instead -- signing and identifying want opposite things
        // here, which is why the session keeps both.
        Session session;
        session.m_agentId = canonicalAgentId(numericAgentId);
        session.m_signedAgentId = agentId;
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
        catch (const CmacKeyError&)
        {
            // This one agent's key is the wrong length. Expected in normal operation (a corrupted
            // key column), reported to the operator -- throttled -- from errorResponseFor()'s
            // MissingKey branch, so nothing extra is logged here.
            return AuthError::MissingKey;
        }
        catch (const std::exception& e)
        {
            // CmacProviderError and anything else unexpected: AES-CMAC itself is unavailable, so
            // EVERY agent will fail to authenticate until this is fixed. Previously this was
            // swallowed and reported as an ordinary bad key, which made a total, permanent
            // authentication outage completely invisible.
            //
            // The agent still receives the generic 401 (see publicErrorFor), which is wrong-ish --
            // it tells the agent its credentials are bad when the manager is what is broken, so an
            // agent may re-enroll instead of retrying. Fixing that needs a new AuthError mapped to
            // 503 and is deliberately left as a follow-up; surfacing it in the log is the urgent half.
            if (const auto d = cmacUnavailableThrottle().record())
            {
                LOGFN_ERROR(logFn(),
                            "AES-CMAC is unavailable, so every agent request will fail authentication (%llu "
                            "occurrence(s) in the last %d s): %s",
                            static_cast<unsigned long long>(d.total),
                            remoted::common::LogThrottle::kDefaultWindowSeconds,
                            e.what());
            }
            return AuthError::MissingKey;
        }

        session.m_cmac->update("WAZUH-REQUEST\n");
        session.m_cmac->update(session.m_protocolVersion);
        session.m_cmac->update("\n");
        session.m_cmac->update(session.m_method);
        session.m_cmac->update("\n");
        session.m_cmac->update(session.m_requestTarget);
        session.m_cmac->update("\n");
        session.m_cmac->update(session.m_signedAgentId);
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
        return AuthError::None;
    }

    std::variant<AuthenticatedRequest, AuthError> AuthMiddleware::Session::finish()
    {
        const auto mac = m_cmac->finalize();
        if (!constantTimeEquals(mac.data(), m_expectedMac.data(), mac.size()))
        {
            return AuthError::InvalidMac;
        }

        // Identity only. The verified body is attached by the transport/gateway as a
        // zero-copy Payload view into its single request buffer -- the middleware never
        // buffers the body (the AES-CMAC above consumed it incrementally).
        AuthenticatedRequest req;
        req.agentId = std::move(m_agentId);
        req.protocolVersion = std::move(m_protocolVersion);
        req.method = std::move(m_method);
        req.requestTarget = std::move(m_requestTarget);
        return req;
    }

} // namespace remoted::auth
