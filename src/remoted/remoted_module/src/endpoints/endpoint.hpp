/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 22, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_ENDPOINT_HPP

#include "auth/authTypes.hpp"          // remoted::auth::AuthenticatedRequest
#include "http_server/IHttpServer.hpp" // remoted::http::{HttpRequest,HttpResponse,IHttpResponder,Method}

#include <wazuh_metrics/iManager.hpp>

#include <functional>
#include <memory>
#include <string_view>

namespace remoted::endpoints
{

    // Shared types an endpoint unit needs, re-exported so a new endpoint includes
    // only this contract header (plus its own logic). As more endpoints are added,
    // each lives in its own folder under src/endpoints/<name>/ and depends on this.
    using remoted::auth::AuthenticatedRequest;
    using remoted::http::HttpRequest;
    using remoted::http::HttpResponse;
    using remoted::http::IHttpResponder;
    using remoted::http::Method;

    /**
     * @brief Post-authentication endpoint handler.
     *
     * Invoked only after the AES-CMAC validation succeeds, with the verified request
     * and the responder. Asynchronous by contract: the handler owns delivering the
     * response and may do so inline or later, from any thread (it runs on the
     * server's worker pool, so it never stalls the I/O threads). It must call
     * responder->send(...) exactly once.
     *
     * The request is a shared_ptr<const> so a handler may retain it across deferred
     * pipeline stages without copying the verified payload.
     */
    using AuthenticatedHandler =
        std::function<void(std::shared_ptr<const AuthenticatedRequest>, std::shared_ptr<IHttpResponder>)>;

    // The remoted.auth.reject.* name catalog: one counter per operator-distinguishable rejection
    // cause, counted at errorResponseFor() -- the single funnel every client-visible auth
    // rejection passes through -- with the PRE-collapse reason (publicErrorFor() deliberately
    // folds the credential failures into one generic 401 on the wire).
    constexpr auto METRIC_AUTH_REJECT_UNKNOWN_AGENT {"remoted.auth.reject.unknown_agent"};
    constexpr auto METRIC_AUTH_REJECT_INVALID_MAC {"remoted.auth.reject.invalid_mac"};
    constexpr auto METRIC_AUTH_REJECT_CLOCK_SKEW {"remoted.auth.reject.clock_skew"};
    constexpr auto METRIC_AUTH_REJECT_UNUSABLE_KEY {"remoted.auth.reject.unusable_key"};
    constexpr auto METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED {"remoted.auth.reject.address_not_allowed"};
    constexpr auto METRIC_AUTH_REJECT_ENROLLMENT_KEY {"remoted.auth.reject.enrollment_key_unavailable"};
    constexpr auto METRIC_AUTH_REJECT_PAYLOAD_MISMATCH {"remoted.auth.reject.payload_mismatch"};
    constexpr auto METRIC_AUTH_REJECT_BODY_TOO_LARGE {"remoted.auth.reject.body_too_large"};
    constexpr auto METRIC_AUTH_REJECT_BAD_ENCODING {"remoted.auth.reject.bad_encoding"};
    constexpr auto METRIC_AUTH_REJECT_MALFORMED {"remoted.auth.reject.malformed"};

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
        std::shared_ptr<wazuh::metrics::ICounter> unknownAgent;      ///< Agent id not in client.keys.
        std::shared_ptr<wazuh::metrics::ICounter> invalidMac;        ///< AES-CMAC did not verify.
        std::shared_ptr<wazuh::metrics::ICounter> clockSkew;         ///< Timestamp outside the window.
        std::shared_ptr<wazuh::metrics::ICounter> unusableKey;       ///< client.keys entry does not decode.
        std::shared_ptr<wazuh::metrics::ICounter> addressNotAllowed; ///< Peer address outside the agent's ip column.
        std::shared_ptr<wazuh::metrics::ICounter> enrollmentKey; ///< /enroll: the enrollment password key is unusable.
        std::shared_ptr<wazuh::metrics::ICounter> payloadMismatch; ///< Authenticated agent claimed another id.
        std::shared_ptr<wazuh::metrics::ICounter> bodyTooLarge;    ///< Over the authenticated-body cap.
        std::shared_ptr<wazuh::metrics::ICounter> badEncoding;     ///< Unsupported/undecodable Content-Encoding.
        std::shared_ptr<wazuh::metrics::ICounter> malformed;       ///< Missing/malformed auth or protocol headers.
    };

    /// Resolves the remoted.auth.reject.* family on @p manager (creating it on first call;
    /// totals carry over on later calls because getOrCreateCounter dedupes by name).
    inline AuthRejectMetrics makeAuthRejectMetrics(wazuh::metrics::IManager& manager)
    {
        return AuthRejectMetrics {
            manager.getOrCreateCounter(
                METRIC_AUTH_REJECT_UNKNOWN_AGENT, "Rejections: the agent id is not in client.keys", "count"),
            manager.getOrCreateCounter(
                METRIC_AUTH_REJECT_INVALID_MAC, "Rejections: the request's AES-CMAC did not verify", "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_CLOCK_SKEW,
                                       "Rejections: timestamp outside the window set by "
                                       "'remoted.auth_max_request_age' and 'remoted.auth_max_future_skew'",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_UNUSABLE_KEY,
                                       "Rejections: the agent's client.keys entry does not decode to a usable AES key",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_ADDRESS_NOT_ALLOWED,
                                       "Rejections: the peer address does not satisfy the agent's client.keys ip "
                                       "column (re-enroll the agent with the address it connects from, or 'any')",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_ENROLLMENT_KEY,
                                       "Rejections: Password-mode POST /enroll could not use the enrollment password "
                                       "key -- etc/authd.pass missing, unreadable, invalid or not yet synced to this "
                                       "worker, or AES-CMAC unavailable. NOT an agent credential fault: no agent "
                                       "exists yet, so re-enrolling fixes nothing",
                                       "count"),
            manager.getOrCreateCounter(
                METRIC_AUTH_REJECT_PAYLOAD_MISMATCH,
                "Rejections: an authenticated agent submitted a payload claiming another agent id (security signal)",
                "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_BODY_TOO_LARGE,
                                       "Rejections: body over 'remoted.auth_max_body_size', or a zstd frame that "
                                       "did not fit the 'remoted.max_inflight_bytes' budget",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_BAD_ENCODING,
                                       "Rejections: unsupported or undecodable Content-Encoding (zstd)",
                                       "count"),
            manager.getOrCreateCounter(METRIC_AUTH_REJECT_MALFORMED,
                                       "Rejections: missing/malformed authorization or protocol-version headers",
                                       "count")};
    }

    /**
     * @brief Installs the process-wide instance errorResponseFor() counts on.
     *
     * Process-wide state on purpose, same precedent as errorResponseFor()'s own throttles:
     * endpoint.cpp has no object to hang it off, and threading a struct through
     * AuthGateway -> every endpoint -> errorResponseFor()'s signature would touch every
     * endpoint and test for no functional gain. NOT safe against concurrent re-install: the
     * facade calls this from start(), under its lifecycle lock, before any route serves --
     * idempotent across restarts because the counters dedupe by name on the never-reset
     * manager. Tests that install must do so sequentially with request traffic.
     */
    void installAuthRejectMetrics(AuthRejectMetrics metrics);

    /**
     * @brief Builds the client-visible {"error","code"} response for an AuthError.
     *
     * Single source of truth for that response shape, shared by AuthGateway (auth-protocol
     * failures) and any endpoint that raises an AuthError of its own after authentication
     * succeeds (e.g. stateless::validatePayloadIdentity()'s PayloadAgentMismatch).
     *
     * Also the single place every client-visible rejection is logged, with the reason BEFORE
     * publicErrorFor() collapses it (see endpoint.cpp): operator-actionable causes -- clock skew,
     * body-cap, unusable key, agent-id mismatch -- become throttled warnings naming the relevant
     * setting, while client-fault rejections stay at debug so an unauthenticated peer cannot flood
     * wazuh-manager.log.
     *
     * @param err          The rejection reason.
     * @param agentContext Optional authenticated agent id, included in the agent-id-mismatch
     *                     warning. Only endpoints that reject AFTER authentication have one.
     */
    remoted::http::HttpResponse errorResponseFor(remoted::auth::AuthError err, std::string_view agentContext = {});

} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_ENDPOINT_HPP
