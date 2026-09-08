/*
 * Wazuh remoted module - /cacerts endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * September 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_CACERTS_METRICS_HPP
#define _REMOTED_ENDPOINTS_CACERTS_METRICS_HPP

/**
 * @file cacertsMetrics.hpp
 * @brief The `GET /cacerts` counter catalog (`remoted.cacerts.*`) plus the names of the listener
 *        certificate pulls (`remoted.server.tls.*`) on the shared `wazuh_metrics` registry.
 *
 * Same shape as downloadMetrics.hpp: resolve once via makeCacertsMetrics() (cold path), every
 * inc* afterwards is a single relaxed atomic op, and a default-constructed struct is the null
 * object that counts nothing. NEVER exposed through the public HTTPS endpoint.
 *
 * These are the WHY behind the endpoint's answers; the WHAT (status cells) is the
 * `remoted.http.cacerts.responses.*` family the handler counts through a MeteredResponder. The
 * two `remoted.server.tls.*` pulls are registered by the facade over IHttpServer::certificateStatus()
 * (they read the transport's evaluation, not this endpoint), their names live here so the whole
 * certificate-distribution vocabulary is declared in one place.
 */

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::endpoints::cacerts
{
    // The remoted.cacerts.* name catalog.
    constexpr auto METRIC_CACERTS_SERVED {"remoted.cacerts.served"};
    constexpr auto METRIC_CACERTS_NOT_FOUND {"remoted.cacerts.not_found"};
    constexpr auto METRIC_CACERTS_CA_MISMATCH {"remoted.cacerts.ca_mismatch"};

    // The remoted.server.tls.* pulls (registered by the facade, read from the transport).
    constexpr auto METRIC_TLS_CERT_EXPIRY_DAYS {"remoted.server.tls.cert_expiry_days"};
    constexpr auto METRIC_TLS_CA_MATCHES_LEAF {"remoted.server.tls.ca_matches_leaf"};

    /**
     * @brief The /cacerts counter set, pre-resolved from one manager.
     *
     * Default-constructed (all null) it counts nothing -- the null object the tests rely on.
     */
    struct CacertsMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> served;     ///< 200s: the CA PEM was handed out.
        std::shared_ptr<wazuh::metrics::ICounter> notFound;   ///< 404s: the CA file is missing, unreadable
                                                              ///< or carries no certificate.
        std::shared_ptr<wazuh::metrics::ICounter> caMismatch; ///< 503s: the CA on disk does not sign the
                                                              ///< served certificate (refused, not served).
    };

    /// Resolves the remoted.cacerts.* family on @p manager (creating it on first call; totals
    /// carry over on later calls because getOrCreateCounter dedupes by name).
    inline CacertsMetrics makeCacertsMetrics(wazuh::metrics::IManager& manager)
    {
        return CacertsMetrics {
            manager.getOrCreateCounter(METRIC_CACERTS_SERVED, "200s: the CA certificate PEM was served", "count"),
            manager.getOrCreateCounter(
                METRIC_CACERTS_NOT_FOUND, "404s: the CA file is missing, unreadable or has no certificate", "count"),
            manager.getOrCreateCounter(METRIC_CACERTS_CA_MISMATCH,
                                       "503s: refused because the configured CA does not sign the served certificate",
                                       "count")};
    }

    // const&: called from the endpoint's value-capturing (non-mutable) lambda; add() mutates
    // the counter, not the struct.
    inline void incServed(const CacertsMetrics& m)
    {
        if (m.served)
        {
            m.served->add();
        }
    }
    inline void incNotFound(const CacertsMetrics& m)
    {
        if (m.notFound)
        {
            m.notFound->add();
        }
    }
    inline void incCaMismatch(const CacertsMetrics& m)
    {
        if (m.caMismatch)
        {
            m.caMismatch->add();
        }
    }

} // namespace remoted::endpoints::cacerts

#endif // _REMOTED_ENDPOINTS_CACERTS_METRICS_HPP
