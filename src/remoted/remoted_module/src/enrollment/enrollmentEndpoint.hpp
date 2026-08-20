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
#include "decoding/iBodyDecoder.hpp" // remoted::decoding::IBodyDecoder
#include "enrollmentAuthenticator.hpp"
#include "enrollmentConfig.hpp"
#include "http_server/IHttpServer.hpp" // remoted::http::RouteHandler
#include "metrics.hpp"

#include <memory>

namespace remoted::enrollment
{

    /**
     * @brief Builds the `POST /enroll` route handler.
     *
     * Registered directly on IHttpServer (see remotedModuleFacade.hpp) -- NOT through AuthGateway --
     * because an enrolling agent has no client.keys entry yet, so the agent<->manager AES-CMAC
     * protocol cannot authenticate it. The returned handler:
     *   1. Answers 403 immediately if @p config.enrollmentEnabled is false, before touching the
     *      authenticator or the bridge -- the route always exists (never a 404); this is what
     *      lets an operator/agent tell "unsupported" apart from "administratively off".
     *   2. Runs @p authenticator against the raw request (mode fixed at facade-construction time
     *      by the listener's client-certificate requirement and authd's <use_password>). The MAC
     *      always covers the wire bytes exactly as sent, compressed or not -- same principle as
     *      AuthGateway (see authGateway.cpp).
     *   3. Runs @p bodyDecoder over the now-verified body, so /enroll honors the manager's
     *      `Content-Encoding: zstd` policy exactly like every other endpoint (`remoted.
     *      http_content_encoding_enabled`) -- decoding only ever happens AFTER authentication, so
     *      an unauthenticated peer can never spend CPU/memory on it.
     *   4. Parses and locally validates the (decoded) JSON body (name/version/groups/ip/key_hash);
     *      rejects malformed input with 400 without ever reaching authd. `force`/`id`/`key` are
     *      never read from the body even if present -- self-enrollment always gets an
     *      auto-assigned ID and an authd-generated key.
     *   5. Resolves the enrollment IP (config.useSourceIp -> the HTTPS peer address; else the
     *      body's `ip`; else "any") and forwards to authd via @p authdClient, deferring the
     *      response until its callback fires.
     *   6. Maps authd's result to the HTTP response (200 + {id,name,ip,key}; a mapped status for
     *      a business-rejection authd code; 503 for a transport failure/timeout).
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
                                            std::shared_ptr<const remoted::decoding::IBodyDecoder> bodyDecoder);

} // namespace remoted::enrollment
