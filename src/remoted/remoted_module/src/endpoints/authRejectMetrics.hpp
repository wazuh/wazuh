/*
 * Wazuh remoted module - Authentication rejection metrics
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_AUTH_REJECT_METRICS_HPP
#define _REMOTED_ENDPOINTS_AUTH_REJECT_METRICS_HPP

/**
 * @file authRejectMetrics.hpp
 * @brief The authentication-rejection counter catalog (`remoted.auth.reject.*`) on the shared
 *        `wazuh_metrics` registry.
 *
 * Counted by errorResponseFor() (endpoint.hpp/.cpp) on the process-wide instance
 * installAuthRejectMetrics() installs; endpoint.hpp includes this header, so every endpoint
 * still reaches the catalog through the endpoint contract.
 */

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::endpoints
{
    // The remoted.auth.reject.* name catalog: one counter per operator-distinguishable rejection
    // cause, counted at errorResponseFor() -- the single funnel every client-visible auth
    // rejection passes through -- with the PRE-collapse reason (publicErrorFor() deliberately
    // folds the credential failures into one generic 401 on the wire).
    constexpr auto METRIC_AUTH_REJECT_UNKNOWN_AGENT {"remoted.auth.reject.unknown_agent"};
    constexpr auto METRIC_AUTH_REJECT_INVALID_SIGNATURE {"remoted.auth.reject.invalid_signature"};
    constexpr auto METRIC_AUTH_REJECT_BAD_TOKEN {"remoted.auth.reject.bad_token"};
    constexpr auto METRIC_AUTH_REJECT_IDENTITY_MISMATCH {"remoted.auth.reject.identity_mismatch"};
    constexpr auto METRIC_AUTH_REJECT_CLOCK_SKEW {"remoted.auth.reject.clock_skew"};
    constexpr auto METRIC_AUTH_REJECT_UNUSABLE_KEY {"remoted.auth.reject.unusable_key"};
    constexpr auto METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED {"remoted.auth.reject.address_not_allowed"};
    constexpr auto METRIC_AUTH_REJECT_ENROLLMENT_KEY {"remoted.auth.reject.enrollment_key_unavailable"};
    constexpr auto METRIC_AUTH_REJECT_PAYLOAD_MISMATCH {"remoted.auth.reject.payload_mismatch"};
    constexpr auto METRIC_AUTH_REJECT_BODY_TOO_LARGE {"remoted.auth.reject.body_too_large"};
    constexpr auto METRIC_AUTH_REJECT_BAD_ENCODING {"remoted.auth.reject.bad_encoding"};
    constexpr auto METRIC_AUTH_REJECT_MALFORMED {"remoted.auth.reject.malformed"};
    constexpr auto METRIC_AUTH_REJECT_TOKEN_UNKNOWN {"remoted.auth.reject.token_unknown"};
    constexpr auto METRIC_AUTH_REJECT_TOKEN_EXPIRED {"remoted.auth.reject.token_expired"};
    constexpr auto METRIC_AUTH_REJECT_TOKEN_REVOKED {"remoted.auth.reject.token_revoked"};
    constexpr auto METRIC_AUTH_REJECT_AGENT_BUSY {"remoted.auth.reject.agent_busy"};

    /**
     * @brief The auth-rejection counter set, pre-resolved from one manager.
     *
     * Same shape as control/metrics.hpp: resolve once via makeAuthRejectMetrics() (cold path),
     * then every count is a single relaxed atomic op -- and only on the REJECTION path; a
     * request that authenticates touches none of these. Default-constructed (all null) it
     * counts nothing -- the null object errorResponseFor() runs with until (and unless)
     * installAuthRejectMetrics() is called.
     */
    struct AuthRejectMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> unknownAgent; ///< Agent id not in client.keys.
        std::shared_ptr<wazuh::metrics::ICounter>
            invalidSignature; ///< The bearer's HS256 signature (agent or enroll profile) did not verify.
        std::shared_ptr<wazuh::metrics::ICounter>
            badToken; ///< Bearer is not a wazuh-agent+jwt token (grammar/header/claims).
        std::shared_ptr<wazuh::metrics::ICounter> identityMismatch;  ///< kid / sub / iss disagree (security signal).
        std::shared_ptr<wazuh::metrics::ICounter> clockSkew;         ///< Token outside the accepted time window.
        std::shared_ptr<wazuh::metrics::ICounter> unusableKey;       ///< client.keys entry does not decode.
        std::shared_ptr<wazuh::metrics::ICounter> addressNotAllowed; ///< Peer address outside the agent's ip column.
        std::shared_ptr<wazuh::metrics::ICounter> enrollmentKey; ///< /enroll: the enrollment password key is unusable.
        std::shared_ptr<wazuh::metrics::ICounter> payloadMismatch; ///< Authenticated agent claimed another id.
        std::shared_ptr<wazuh::metrics::ICounter> bodyTooLarge;    ///< Over the authenticated-body cap.
        std::shared_ptr<wazuh::metrics::ICounter> badEncoding;     ///< Unsupported/undecodable Content-Encoding.
        std::shared_ptr<wazuh::metrics::ICounter> malformed;       ///< Missing/malformed auth or protocol headers.
        std::shared_ptr<wazuh::metrics::ICounter>
            tokenUnknown; ///< /enroll: the bearer's `kid` names no credential-bearing enrollment token.
        std::shared_ptr<wazuh::metrics::ICounter> tokenExpired; ///< /enroll: the enrollment token has lapsed.
        std::shared_ptr<wazuh::metrics::ICounter> tokenRevoked; ///< /enroll: the enrollment token was revoked.
        std::shared_ptr<wazuh::metrics::ICounter> agentBusy;    ///< The agent already had its cap of open requests.
    };

    /// Resolves the remoted.auth.reject.* family on @p manager (creating it on first call;
    /// totals carry over on later calls because getOrCreateCounter dedupes by name).
    inline AuthRejectMetrics makeAuthRejectMetrics(wazuh::metrics::IManager& manager)
    {
        return AuthRejectMetrics {
            manager.getOrCreateCounter(
                METRIC_AUTH_REJECT_UNKNOWN_AGENT, "Rejections: the agent id is not in client.keys", "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_INVALID_SIGNATURE,
                                       "Rejections: the bearer token's signature did not verify with the agent's key "
                                       "(wrong key or tampering); /enroll's wazuh-enroll+jwt failures also land here",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_BAD_TOKEN,
                                       "Rejections: the bearer is not a valid wazuh-agent+jwt token (size, grammar, "
                                       "header, claim set/types, jti, or exp-iat > 60 s)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_IDENTITY_MISMATCH,
                                       "Rejections: a correctly signed token whose kid, sub and iss do not name the "
                                       "same agent (security signal)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_CLOCK_SKEW,
                                       "Rejections: token issued in the future, expired, or older than the accepted "
                                       "age ('remoted.jwt_max_age' / 'remoted.jwt_clock_skew')",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_UNUSABLE_KEY,
                                       "Rejections: the agent's client.keys entry does not decode to a 32-byte key",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED,
                                       "Rejections: the peer address does not satisfy the agent's client.keys ip "
                                       "column (re-enroll the agent with the address it connects from, or 'any')",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_ENROLLMENT_KEY,
                                       "Rejections: Password-mode POST /enroll could not use the enrollment password "
                                       "key -- etc/authd.pass missing, unreadable, invalid or not yet synced to this "
                                       "worker, or HKDF unavailable. NOT an agent credential fault: no agent "
                                       "exists yet, so re-enrolling fixes nothing",
                                       "count"),
            manager.getOrCreateCounter(
                METRIC_AUTH_REJECT_PAYLOAD_MISMATCH,
                "Rejections: an authenticated agent submitted a payload claiming another agent id (security signal)",
                "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_BODY_TOO_LARGE,
                                       "Rejections: body over 'remoted.auth_max_body_size', or a zstd body that "
                                       "would decode past 'remoted.auth_max_decoded_body_size' or did not fit the "
                                       "'remoted.max_inflight_bytes' budget",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_BAD_ENCODING,
                                       "Rejections: unsupported or undecodable Content-Encoding (zstd)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_MALFORMED,
                                       "Rejections: missing/malformed authorization or protocol-version headers",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_TOKEN_UNKNOWN,
                                       "Rejections: POST /enroll with an enrollment-token bearer whose kid names no "
                                       "credential-bearing token in etc/enrollment_tokens.json, even after a "
                                       "forced re-read (never minted, minted without a credential, or not yet "
                                       "synchronized to this node)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_TOKEN_EXPIRED,
                                       "Rejections: POST /enroll with a correctly signed enrollment-token bearer "
                                       "whose token is past its expiry (mint a new one)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_TOKEN_REVOKED,
                                       "Rejections: POST /enroll with a correctly signed enrollment-token bearer "
                                       "whose token was revoked by the operator",
                                       "count"),
            manager.getOrCreateCounter(
                METRIC_AUTH_REJECT_AGENT_BUSY,
                "Rejections: an authenticated agent already held its share -- "
                "'remoted.max_requests_per_agent' open requests or 'remoted.max_inflight_bytes_per_agent' "
                "decoded bytes; answered 503 (never reached by an honest agent with the defaults -- "
                "investigate the agent)",
                "count")};
    }
} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_AUTH_REJECT_METRICS_HPP
