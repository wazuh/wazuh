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

#pragma once

#include "remoted_module.h"

#include "jwt/jwtProfileV1.hpp"
#include "jwt/jwtVerifyError.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

namespace remoted::auth
{

    /// @brief Canonical numeric form of an agent id -- an agent id is always numeric by design
    /// (assigned sequentially by authd), even though it travels as text on the wire (Authorization
    /// header, client.keys, the /stateless payload's wazuh.agent.id).
    using AgentId = std::uint32_t;

    /**
     * @brief Zero-copy view of the verified request body, with explicit release.
     *
     * The bytes are NOT owned here: they live in a single transport-owned buffer
     * that this holder keeps alive via an opaque keep-alive (a shared_ptr to the
     * transport's request context, which also carries the in-flight byte
     * reservation). So there is exactly one physical copy of the payload.
     *
     * Lifetime contract: bytes() is valid until the payload is released -- either
     * by destroying the owning AuthenticatedRequest (RAII) or by calling release()
     * explicitly (e.g. once the handler has forwarded the body downstream and only
     * needs the responder afterwards). Releasing drops the keep-alive, freeing the
     * buffer and restoring the byte budget. Confine a payload to one thread.
     */
    class Payload
    {
    public:
        Payload() = default;

        Payload(std::string_view view, std::shared_ptr<const void> keepAlive)
            : m_keepAlive {std::move(keepAlive)}
            , m_view {view}
        {
        }

        /// @return The body bytes, or an empty view once released.
        std::string_view bytes() const noexcept
        {
            return m_keepAlive ? m_view : std::string_view {};
        }

        std::size_t size() const noexcept
        {
            return bytes().size();
        }

        bool empty() const noexcept
        {
            return bytes().empty();
        }

        /**
         * @brief Release the underlying buffer and the in-flight byte reservation now.
         *
         * Idempotent. After this, bytes() is empty. Const because it manages the
         * payload's lifetime, not the (const) identity of the request that owns it.
         */
        void release() const noexcept
        {
            m_keepAlive.reset();
            m_view = {};
        }

    private:
        mutable std::shared_ptr<const void> m_keepAlive; ///< Pins the transport buffer + byte reservation.
        mutable std::string_view m_view;                 ///< View into that buffer; empty once released.
    };

    /**
     * @brief Identity + payload an endpoint handler receives once the bearer token has
     *        been verified.
     *
     * This struct is the contract between the transport and endpoint-specific
     * code, so it must never carry a transport-specific type. The small identity
     * fields are owned (they outlive an early payload release); the body is a
     * zero-copy Payload view (see above).
     */
    struct AuthenticatedRequest
    {
        std::string agentId;         ///< Verified agent id, canonical (the token's `sub`, never the raw header).
        std::string protocolVersion; ///< Value of the protocol-version header.
        std::string method;          ///< Uppercase HTTP method, e.g. "POST".
        std::string requestTarget;   ///< Raw path + query, exactly as received.
        Payload payload;             ///< Verified request body (a view into the single transport buffer).
        /// When the auth gateway picked the request up (stamped once, before authentication
        /// runs). Feeds the remoted.http.<endpoint>.latency histograms: end-to-end time is
        /// measured from here to response delivery. steady_clock so an NTP step can't produce
        /// negative or wild durations. Default (epoch) means "never stamped" -- consumers skip
        /// the observation rather than record a bogus span.
        std::chrono::steady_clock::time_point receivedAt {};
    };

    /**
     * @brief Internal auth failure reason, safe to log.
     *
     * Every credential-related reason is a 401 with the same generic message; what the wire DOES
     * name (issue #38993, RFC 6750 `error_description` and the body's `code`) is the public CLASS
     * publicErrorFor() maps it to -- `unknown_agent` (re-enroll), `stale_token` (fix the clock and
     * retry), `invalid_signature` (do not re-enroll), the `token_*` of /enroll, `invalid_request`
     * (no usable credential presented) -- which is coarser than this enum: several reasons share a
     * class, and the finer cause stays in the log and in remoted.auth.reject.*. Protocol-version
     * and payload-agent-mismatch are called out as their own 400s, so they keep distinct public
     * messages.
     */
    enum class AuthError
    {
        None = 0,
        MissingProtocolVersion,
        UnsupportedProtocolVersion,
        MissingAuthorization,
        MalformedAuthorization,
        UnknownAgent,
        MissingKey,
        AddressNotAllowed,    ///< The peer address does not satisfy the agent's client.keys ip column
                              ///< (the legacy remoted's ENC_IP_ERROR rejection). Its public class is
                              ///< `invalid_signature`, not `unknown_agent`: the agent must not re-enroll
                              ///< over it (the id exists; the operator fixes the column), and ids being
                              ///< sequential, revealing their existence buys an attacker nothing (T10).
        InvalidToken,         ///< The bearer is not a `wazuh-agent+jwt` token: size, compact grammar,
                              ///< base64url, JSON, header/claim sets or types, jti, or the structural
                              ///< time rules (nbf == iat, exp > iat, exp - iat <= 60).
        InvalidSignature,     ///< The HS256 signature does not verify with the agent's key.
        StaleToken,           ///< Clock-relative rejection: issued in the future, expired, or older than
                              ///< the accepted age (AuthConfig::timePolicy).
        IdentityMismatch,     ///< `sub` / `iss` do not name the agent `kid` names.
        PayloadAgentMismatch, ///< Raised by POST /stateless's pre-forward check (statelessEndpoint.cpp):
                              ///< the H-line JSON is missing/malformed, or wazuh.agent.id is
                              ///< missing/not-a-string/not-numeric, or doesn't match the authenticated
                              ///< agent id.
        BodyTooLarge,
        UnsupportedContentEncoding, ///< Content-Encoding present but not (case-insensitively) "zstd".
        MalformedContentEncoding,   ///< Content-Encoding: zstd, but the body isn't a valid/complete
                                    ///< zstd frame (bad magic, truncated, oversized window, ...).
        EnrollmentKeyUnavailable,   ///< Raised ONLY by EnrollmentAuthenticator's Password mode
                                    ///< (enrollmentAuthenticator.cpp): etc/authd.pass is missing,
                                    ///< unreadable, invalid, or not yet synced from the master to this
                                    ///< node, OR the HKDF provider is unavailable manager-wide. Deliberately
                                    ///< distinct from MissingKey (a client.keys decode failure for an
                                    ///< ALREADY-enrolled agent) -- collapsing the two would have
                                    ///< logRejection() tell an operator to "re-enroll the affected
                                    ///< agent(s)" for a condition where no agent, and no client.keys
                                    ///< entry, exists yet at all.
        TokenUnknown,               ///< Raised ONLY by EnrollmentAuthenticator's enrollment-token path
                                    ///< (issue #38993): the bearer's `kid` names a token id that is not in
                                    ///< the replicated store (etc/enrollment_tokens.json) even after a
                                    ///< forced re-read -- never minted, minted without a credential, or
                                    ///< not yet synchronized to this node.
        TokenExpired,               ///< Same path: a correctly signed token bearer whose token is past
                                    ///< its `expires`. Distinct from StaleToken (the JWT's own iat/exp
                                    ///< window): the credential itself has lapsed, not this request.
        TokenRevoked,               ///< Same path: a correctly signed token bearer whose token the
                                    ///< operator revoked. Like the two above it is a 401 whose class names
                                    ///< it on the wire (`token_revoked`) and counts in its own
                                    ///< remoted.auth.reject.token_* cell.
    };

    /**
     * @brief What AuthMiddleware::authenticate() hands back on success: the identity every
     *        consumer downstream may trust, and nothing else.
     */
    struct VerifiedAgent
    {
        std::string agentId; ///< Canonical form ("001"): the token's verified `sub`, equal to `kid`.
    };

    /**
     * @brief Render an AuthError as a lowercase_snake_case tag, for logging.
     *
     * @param err Error to render.
     * @return Static string; never null.
     */
    const char* toString(AuthError err);

    /**
     * @brief Client-visible HTTP status, message and -- for a 401 -- the authentication failure
     *        class and the RFC 6750 challenge that names it.
     *
     * All four are static literals: the funnel that renders them (endpoints/endpoint.cpp's
     * errorResponseFor()) runs on every rejected request and must stay allocation-free.
     */
    struct PublicError
    {
        int status;            ///< HTTP status code to send back to the client.
        const char* message;   ///< Static, human-readable message; never null.
        const char* code;      ///< The public class of a 401 (`unknown_agent`, `stale_token`,
                               ///< `invalid_signature`, `invalid_request`, `enrollment_key_unavailable`,
                               ///< `token_unknown`, `token_expired`, `token_revoked`): the body's `code`
                               ///< and the challenge's `error_description`. nullptr for every other
                               ///< status, whose body `code` is the status itself.
        const char* challenge; ///< The full `WWW-Authenticate` value of a 401 (RFC 6750 §3):
                               ///< `Bearer error="invalid_token", error_description="<code>"` for a
                               ///< credential that was judged and failed, `Bearer error="invalid_request"`
                               ///< when none was usable, a bare `Bearer` when the server could not judge
                               ///< it at all (enrollment key unavailable). nullptr when there is no
                               ///< challenge (every non-401).
    };

    /**
     * @brief Single source of truth for the client-visible status/message/class/challenge.
     *
     * Shared by every transport so they all answer identically instead of each re-deriving the
     * error-response mapping. The class is deliberately coarser than AuthError (issue #38993, T10):
     * it tells the AGENT what to do -- `unknown_agent`: re-enroll; `stale_token`: fix the clock and
     * retry; `invalid_signature`: keep the credential, do NOT re-enroll (a signature, token-shape,
     * identity, address or unusable-key failure is never fixed by a new identity); `token_*`: the
     * enrollment token's own state; `invalid_request`: no usable credential was presented -- while
     * the finer cause is logged and counted in remoted.auth.reject.*.
     *
     * @param err Internal failure reason returned by AuthMiddleware.
     * @return What the transport must send to the client.
     */
    PublicError publicErrorFor(AuthError err);

    /**
     * @brief The only `protocol-version` header value this manager accepts.
     *
     * A protocol constant, not an ops tuning knob -- which is why it is not C-ABI driven. Named
     * here rather than spelled inline so that EVERY authenticated scheme reads the same value:
     * both the agent<->manager bearer-JWT middleware (AuthConfig below) and the enrollment scheme
     * (EnrollmentAuthConfig) default to it, so the two can never drift into accepting different
     * versions -- and neither can hardcode a literal that silently disagrees with what it
     * validates.
     */
    inline constexpr std::string_view kSupportedProtocolVersion {"1"};

    /**
     * @brief Maps a verifier failure class onto the AuthError taxonomy. Shared by the
     *        `wazuh-agent+jwt` middleware and the `wazuh-enroll+jwt` enrollment authenticator so
     *        the same verifier outcome always counts in the same metric cell.
     */
    AuthError toAuthError(jwt_profile::v1::VerifyError error);

    /**
     * @brief Auth-protocol tunables shared by every transport.
     *
     * Every transport implementation must configure the exact same knobs the
     * same way.
     */
    struct AuthConfig
    {
        std::string supportedProtocolVersion {kSupportedProtocolVersion}; ///< Expected protocol-version header.
        /// Accepted token age and clock skew for the `wazuh-agent+jwt` bearer: the profile defaults
        /// (60 s / 30 s) unless remoted's `remoted.jwt_max_age` / `remoted.jwt_clock_skew` internal
        /// options change them, within the profile ceiling (43200 s / 43200 s -- C-ABI `jwt_max_age`
        /// / `jwt_clock_skew`, see buildAuthConfig()).
        jwt_profile::v1::TimePolicy timePolicy {};
        std::size_t maxBodySize = 10 * 1024 * 1024; ///< Hard cap on the authenticated body size (10 MiB).
    };

    /**
     * @brief Translate the module's C-ABI config into an AuthConfig.
     *
     * Every field resolves as **caller value (C-ABI struct) -> built-in default**, same pattern as
     * remoted::http::buildHttpServerConfig(). `supportedProtocolVersion` is not C-ABI driven --
     * it's a protocol constant, not an ops tuning knob.
     *
     * The time policy is the one place a value can be rejected rather than defaulted: an unset
     * value (`jwt_max_age <= 0`; `jwt_clock_skew` without `jwt_clock_skew_set` -- zero skew is a
     * valid setting) takes the profile default (60 s / 30 s), but a configured value outside the
     * profile ceiling (1..43200 / 0..43200, which remoted's own getDefine_Int_default() range
     * already prevents) throws std::invalid_argument -- the module must never start with a wider
     * window than the profile allows.
     *
     * @throw std::invalid_argument if jwt_max_age > 43200, or jwt_clock_skew_set with a skew outside 0..43200.
     *
     * @param config Configuration handed by remoted.
     * @return Resolved AuthConfig.
     */
    AuthConfig buildAuthConfig(const remoted_module_config_t& config);

    /**
     * @brief The C-ABI `jwt_max_age` / `jwt_clock_skew` (+ `jwt_clock_skew_set`) fields as a
     *        TimePolicy: unset -> profile default (60 s / 30 s); configured values validated
     *        (throws std::invalid_argument outside the profile ceiling, zero skew included as valid).
     *        Shared by buildAuthConfig() and the enrollment config so both schemes read ONE policy.
     */
    jwt_profile::v1::TimePolicy buildTimePolicy(int jwtMaxAge, int jwtClockSkew, bool jwtClockSkewSet);

} // namespace remoted::auth
