/*
 * Wazuh remoted module - POST /enroll endpoint
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "authdClient.hpp"
#include "common/requestOutcomeMetrics.hpp" // remoted::metrics::EndpointHttpMetrics
#include "decoding/iBodyDecoder.hpp"        // remoted::decoding::IBodyDecoder
#include "enrollmentAuthenticator.hpp"
#include "enrollmentConfig.hpp"
#include "http_server/IHttpServer.hpp" // remoted::http::RouteHandler
#include "metrics.hpp"

#include <cstddef>
#include <functional>
#include <memory>

namespace remoted::enrollment
{

    /// Cap on the /enroll JSON body actually parsed, post-decode -- an endpoint-local guard on
    /// top of the transport's own hard cap and EnrollmentAuthConfig::maxBodySize (the WIRE/
    /// pre-decode size). Public so remotedModuleFacade.hpp can pass the SAME value as the decoded-
    /// size cap on the dedicated BodyDecoder instance /enroll uses -- see makeHandler()'s doc
    /// comment on why /enroll needs its own (smaller) cap there, unlike AuthGateway's shared one.
    inline constexpr std::size_t kMaxEnrollBodySize = 16U * 1024U;

    /**
     * @brief The rate-limit admissions /enroll charges, one per class of caller.
     *
     * Charged INSIDE the handler, after the checks that cost the manager nothing and before the
     * authd round trip they exist to protect -- not in front of the whole route. A request that
     * fails its credential, its body or its version check is answered without spending anything,
     * so a flood of such requests cannot starve the agents that pass them.
     *
     * Two classes, two buckets, because "passed authenticate()" is not "proved anything" on every
     * path: a re-enrollment bearer is handed to authd unverified (only the master holds its secret)
     * and Open mode admits a credential-less request outright. Anyone can produce those, so they are
     * charged to @c unverified, and so is an enrollment token with no uses left: a spent single-use
     * token is easy to find (install commands, CI logs), and only authd can turn it down. A request
     * whose password or live enrollment token was verified here is charged to @c verified.
     *
     * Each admission returns true to proceed, or false once it has already sent the 429 on the
     * responder it was given. A null admission admits everything.
     */
    struct RateGates
    {
        using Admission = std::function<bool(remoted::http::IHttpResponder&)>;

        Admission verified;   ///< Password- or enrollment-token-verified enrollments.
        Admission unverified; ///< Re-enrollments, credential-less (Open) ones and spent tokens.
    };

    /**
     * @brief Builds the `POST /enroll` route handler.
     *
     * Registered directly on IHttpServer (see remotedModuleFacade.hpp) -- NOT through AuthGateway --
     * because an enrolling agent has no client.keys entry yet, so the agent<->manager
     * `wazuh-agent+jwt` bearer cannot authenticate it. The returned handler:
     *   1. Answers 403 immediately if @p config.enrollmentEnabled is false, before touching the
     *      authenticator or the bridge -- the route always exists (never a 404); this is what
     *      lets an operator/agent tell "unsupported" apart from "administratively off".
     *   2. Runs @p authenticator against the raw request (mode fixed at facade-construction time
     *      by the listener's client-certificate requirement and authd's <use_password>). The MAC
     *      always covers the wire bytes exactly as sent, compressed or not -- same principle as
     *      AuthGateway (see authGateway.cpp).
     *   3. Runs @p bodyDecoder over the now-verified body, so /enroll honors the manager's
     *      `Content-Encoding: zstd` policy exactly like every other endpoint (`remoted.
     *      http_content_encoding_enabled`) -- decoding only ever happens AFTER the freshness/MAC
     *      check in Password mode, so an unauthenticated peer can't reach it THERE. Open mode has
     *      no credential check at all by design, so decoding still runs for anonymous requests in
     *      that mode -- @p bodyDecoder must therefore be an instance capped at kMaxEnrollBodySize
     *      (see remotedModuleFacade.hpp), not the larger shared-budget-sized one AuthGateway's
     *      routes use, so a small, highly-compressed frame can't hold much of the in-flight byte
     *      budget (shared with /stateless and friends) even briefly during decompression.
     *   4. Parses and locally validates the (decoded) JSON body (name/version/groups/ip/key_hash);
     *      rejects malformed input with 400 without ever reaching authd. `force`/`id`/`key` are
     *      never read from the body even if present -- self-enrollment always gets an
     *      auto-assigned ID and an authd-generated key.
     *   5. Charges @p rateGates (see RateGates): only a request that passed every check above
     *      reaches this point, so only those can be refused with 429 -- or spend the allowance.
     *   6. Resolves the enrollment IP (config.useSourceIp -> the HTTPS peer address; else the
     *      body's `ip`; else "any") and forwards to authd via @p authdClient, deferring the
     *      response until its callback fires.
     *   7. Maps authd's result to the HTTP response (200 + {id,name,ip,key}; a mapped status for
     *      a business-rejection authd code; 503 for a transport failure/timeout).
     *
     * @p httpMetrics adds the same remoted.http.<endpoint>.{responses.*,latency} accounting the four
     * AuthGateway endpoints get. /enroll needs its own wiring for it because it is NOT registered
     * through AuthGateway (see above), so nothing stamps a receipt time for it: the handler wraps the
     * responder in a MeteredResponder instead, which times from handler entry and covers every answer
     * -- including the one authd's callback delivers on another thread. Defaulted, so a caller that
     * does not care (the module's own tests) counts nothing.
     *
     * @warning The returned handler stores references to @p authenticator, @p authdClient and
     * @p metrics. The caller must guarantee all three outlive every route registered with this
     * handler, exactly like controlEndpoint::makeHandler()'s ControlHandler& contract. @p
     * bodyDecoder is captured as a shared_ptr copy instead (the same instance AuthGateway holds,
     * per remotedModuleFacade.hpp -- BodyDecoder is stateless, so sharing it is safe).
     */
    remoted::http::RouteHandler makeHandler(const EnrollmentAuthenticator& authenticator,
                                            AuthdClient& authdClient,
                                            const Config& config,
                                            EnrollmentMetrics& metrics,
                                            std::shared_ptr<const remoted::decoding::IBodyDecoder> bodyDecoder,
                                            remoted::metrics::EndpointHttpMetrics httpMetrics = {},
                                            RateGates rateGates = {});

    /**
     * @brief The 429 body this route answers when the endpoint's rate limit refuses a request.
     *
     * Lives here, not in the gate that sends it (endpoints/rateLimitGate.hpp), so /enroll's error
     * envelope stays defined in one place: the nested `{"error":{"code","message"}}` shape every
     * other rejection of this route uses, with `code` 0 -- the same value the envelope carries
     * whenever the refusal is remoted's own rather than an authd numeric code.
     *
     * `Retry-After` is the gate's to add: that one is the limiter's refill time, not an envelope
     * decision.
     */
    remoted::http::HttpResponse rateLimitedResponse();

} // namespace remoted::enrollment
