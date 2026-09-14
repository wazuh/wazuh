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
 *   - 200 `application/x-pem-file`: the CERTIFICATE blocks of the configured file, re-serialised
 *     here from the parsed X.509 objects. A bundle is served as a bundle; anything else the file
 *     carries (a private key, a comment, a CRL) is not part of the answer, because the answer is
 *     built rather than forwarded (issue #39078, H01).
 *   - 404 `{"error":"not_found"}`: the file is missing, unreadable, too large, carries no
 *     certificate, or could not be parsed to its end -- a document we do not fully understand is
 *     refused whole. Same body as the transport's unknown-route 404.
 *   - 503 `{"error":"ca_mismatch"}`: none of those certificates signs the certificate being served
 *     -- handing them out would make every verifying agent fail its handshake against this very
 *     manager, so the endpoint refuses instead.
 *
 * Both the bytes and the verdict come from ONE read of the file, cached under its content hash by
 * CaCertificateSource: a replaced CA is noticed in the request that reads it, not up to a day
 * later (H06). A snapshot with no certificates at all reads "unknown" rather than "mismatch": if
 * the file is unreadable now, the answer is 404, not a refusal.
 */

#include "common/requestOutcomeMetrics.hpp" // remoted::metrics::EndpointHttpMetrics
#include "endpoints/cacertsMetrics.hpp"
#include "http_server/IHttpServer.hpp" // RouteHandler, CaCertificateSnapshot

#include <functional>
#include <string>

namespace remoted::endpoints::cacerts
{
    /// Media type of a successful answer.
    constexpr auto PEM_CONTENT_TYPE {"application/x-pem-file"};

    /**
     * @brief Build the raw route handler for `GET /cacerts`.
     *
     * @param snapshot    Reads the CA file's current state -- the certificates to publish and
     *                    whether they sign the served leaf, from the same read (typically
     *                    IHttpServer::caCertificateSnapshot() through a weak_ptr). A null function
     *                    or an empty snapshot answers 404: there is nothing to hand out.
     * @param metrics     The remoted.cacerts.* counters (the WHY). Copied in; a
     *                    default-constructed set counts nothing.
     * @param httpMetrics The remoted.http.cacerts.responses.* family (the WHAT), counted through a
     *                    MeteredResponder. May be null (counts nothing). Must outlive the handler
     *                    when non-null -- the facade keeps it as a value member, like every other
     *                    endpoint's.
     */
    remoted::http::RouteHandler makeHandler(std::function<remoted::http::CaCertificateSnapshot()> snapshot,
                                            CacertsMetrics metrics,
                                            const remoted::metrics::EndpointHttpMetrics* httpMetrics);

} // namespace remoted::endpoints::cacerts

#endif // _REMOTED_ENDPOINTS_CACERTS_ENDPOINT_HPP
