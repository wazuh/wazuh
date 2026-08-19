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
#include "enrollmentAuthenticator.hpp"
#include "enrollmentConfig.hpp"
#include "http_server/IHttpServer.hpp" // remoted::http::RouteHandler
#include "metrics.hpp"

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
     *      by the listener's client-certificate requirement and authd's <use_password>).
     *   3. Parses and locally validates the JSON body (name/version/groups/ip/key_hash); rejects
     *      malformed input with 400 without ever reaching authd. `force`/`id`/`key` are never
     *      read from the body even if present -- self-enrollment always gets an auto-assigned ID
     *      and an authd-generated key.
     *   4. Resolves the enrollment IP (config.useSourceIp -> the HTTPS peer address; else the
     *      body's `ip`; else "any") and forwards to authd via @p authdClient, deferring the
     *      response until its callback fires.
     *   5. Maps authd's result to the HTTP response (200 + {id,name,ip,key}; a mapped status for
     *      a business-rejection authd code; 503 for a transport failure/timeout).
     *
     * @warning The returned handler stores references to @p authenticator, @p authdClient and
     * @p metrics. The caller must guarantee all three outlive every route registered with this
     * handler, exactly like controlEndpoint::makeHandler()'s ControlHandler& contract.
     */
    remoted::http::RouteHandler makeHandler(const EnrollmentAuthenticator& authenticator,
                                            AuthdClient& authdClient,
                                            const Config& config,
                                            EnrollmentMetrics& metrics);

} // namespace remoted::enrollment
