/*
 * Wazuh remoted module - POST /enroll/secret endpoint
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_REENROLL_SECRET_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_REENROLL_SECRET_ENDPOINT_HPP

#include "common/requestOutcomeMetrics.hpp" // remoted::metrics::EndpointHttpMetrics
#include "endpoint.hpp"                     // AuthenticatedHandler
#include "enrollment/authdClient.hpp"       // remoted::enrollment::AuthdClient
#include "enrollment/metrics.hpp"           // remoted::enrollment::ReenrollSecretMetrics

namespace remoted::endpoints::reenrollsecret
{

    /**
     * @brief Builds the `POST /enroll/secret` route handler (issue #39315).
     *
     * The route an agent that ALREADY holds a client.keys identity calls to obtain the per-agent
     * re-enrollment secret its enrollment never gave it: a 4.x agent upgraded to 5.0 over WPK
     * (it keeps its key, so it never calls POST /enroll), an agent enrolled over port 1515, or an
     * agent whose global.db row was rebuilt from client.keys. Without it, the only credential such
     * an agent holds is its key -- and the moment the manager stops accepting that key, recovery
     * needs an operator at the endpoint with a freshly minted enrollment token.
     *
     * Registered through AuthGateway, so authentication is the existing AuthMiddleware verbatim
     * (protocol-version header, one `Bearer`, the client.keys lookup AND that entry's `ip` column
     * against the peer address, then HS256 over the agent's own key with the
     * 'remoted.jwt_max_age'/'remoted.jwt_clock_skew' time policy).
     *
     * **The secret is minted for the middleware's verified `sub`. There is no id field in the
     * request**, so no request shape exists in which one agent asks about another: agent 002 cannot
     * produce a signature under agent 001's key. This is the same proof the manager already demands
     * before accepting that agent's events or handing it its centralized configuration.
     *
     * The agent's key is NEVER rotated on this path (authd stores the new secret against the
     * existing key), which is what makes a lost response harmless: the agent is left exactly as it
     * was -- valid key, no secret -- and its next start retries. Reissue is always allowed for the
     * same reason; a one-shot gate would strand any agent whose response was lost.
     *
     * Answers:
     *   - `200` -- `{"id":"001","reenroll_secret":"<64 hex>"}`.
     *   - `401` -- the gateway's own classes, plus authd's 9026 (the agent left client.keys between
     *     authentication and authd's answer, or its row does not exist yet). Built through
     *     errorResponseFor(), so it carries the same envelope, `WWW-Authenticate` challenge and
     *     remoted.auth.reject.* accounting every other 401 on this server does.
     *   - `409` -- authd 9030: a rotation for that agent is already in flight. Retry.
     *   - `429` -- the rate limit SHARED with POST /enroll refused it before authentication (the
     *     gate lives in AuthGateway::addAuthenticatedRoute, not here).
     *   - `503` -- authd 9031/9016, authd unreachable, or its bounded queue full. Retry.
     *
     * @warning The returned handler stores references to @p authdClient and @p metrics; both must
     * outlive every route registered with it (same contract as enrollment::makeHandler()).
     * @p httpMetrics is COPIED into a MeteredResponder at handler entry, which is what makes the
     * accounting cover the answer authd's callback delivers on another thread.
     */
    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::enrollment::AuthdClient& authdClient,
                                                         remoted::enrollment::ReenrollSecretMetrics& metrics,
                                                         remoted::metrics::EndpointHttpMetrics httpMetrics = {});

    /**
     * @brief The 429 body this route answers when the shared rate limit refuses a request.
     *
     * Its own, next to the handler, rather than /enroll's: sharing a bucket is not sharing a body.
     * The flat `{"error":"..."}` envelope its own rejections use (the `cacerts` shape), never
     * /enroll's nested numeric one. `Retry-After` is the gate's to add.
     */
    remoted::http::HttpResponse rateLimitedResponse();

} // namespace remoted::endpoints::reenrollsecret

#endif // _REMOTED_ENDPOINTS_REENROLL_SECRET_ENDPOINT_HPP
