/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_CACERTS_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_CACERTS_ENDPOINT_HPP

/**
 * @file cacertsEndpoint.hpp
 * @brief `GET /cacerts`: hands out the CA that signs this listener's certificate
 *        (`remote.https.ca_certificate`), so an agent can bootstrap trust in the manager without
 *        an out-of-band copy of the PEM (RF-27).
 *
 * Unauthenticated by nature (the caller has nothing to authenticate with yet), body-less, and
 * exempt from the in-flight byte budget like the health probe: a trust bootstrap must not be shed
 * under memory pressure. The transport applies the global prefix like it does for every route.
 *
 * Contract:
 *   - 200 `application/x-pem-file`: the file, byte for byte (a bundle is served as a bundle).
 *   - 404 `{"error":"not_found"}`: the file is missing, unreadable or carries no
 *     `-----BEGIN CERTIFICATE-----` block. Same body as the transport's unknown-route 404.
 *   - 503 `{"error":"ca_mismatch"}`: the listener's last evaluation says this CA does NOT sign the
 *     certificate being served -- handing it out would make every verifying agent fail its
 *     handshake against this very manager, so the endpoint refuses instead.
 *
 * The file is read on every request (cold endpoint, tiny file: cheaper than a cache with an
 * invalidation story), so a CA that goes missing is a 404 right away. The coherence verdict comes
 * from the transport's evaluation (start + every certificateStatusInterval), so a CA ROTATED in
 * place is served until the next tick or restart -- documented, with the refresh-on-fingerprint
 * improvement deferred. An evaluation that could not read the CA (nullopt) does not block: if the
 * file is readable now, it is served.
 */

#include "common/requestOutcomeMetrics.hpp" // remoted::metrics::EndpointHttpMetrics
#include "endpoints/cacertsMetrics.hpp"
#include "http_server/IHttpServer.hpp" // RouteHandler, TlsCertificateSnapshot

#include <functional>
#include <string>

namespace remoted::endpoints::cacerts
{
    /// Media type of a successful answer.
    constexpr auto PEM_CONTENT_TYPE {"application/x-pem-file"};

    /**
     * @brief Build the raw route handler for `GET /cacerts`.
     *
     * @param caCertificatePath The PEM to serve (HttpServerConfig::caCertificatePath), read per request.
     * @param status            Reads the listener's latest TlsCertificateSnapshot (typically
     *                          IHttpServer::certificateStatus() through a weak_ptr); a null
     *                          function or a default snapshot means "unknown", which serves.
     * @param metrics           The remoted.cacerts.* counters (the WHY). Copied in; a
     *                          default-constructed set counts nothing.
     * @param httpMetrics       The remoted.http.cacerts.responses.* family (the WHAT), counted
     *                          through a MeteredResponder. May be null (counts nothing). Must
     *                          outlive the handler when non-null -- the facade keeps it as a value
     *                          member, like every other endpoint's.
     */
    remoted::http::RouteHandler makeHandler(std::string caCertificatePath,
                                            std::function<remoted::http::TlsCertificateSnapshot()> status,
                                            CacertsMetrics metrics,
                                            const remoted::metrics::EndpointHttpMetrics* httpMetrics);

} // namespace remoted::endpoints::cacerts

#endif // _REMOTED_ENDPOINTS_CACERTS_ENDPOINT_HPP
