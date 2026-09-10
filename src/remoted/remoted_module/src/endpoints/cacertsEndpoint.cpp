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

#include "cacertsEndpoint.hpp"

#include "common/logThrottle.hpp"

#include "loggerHelper.h"

#include <memory>
#include <string_view>
#include <utility>

namespace remoted::endpoints::cacerts
{
    namespace
    {
        constexpr auto CACERTS_LOGTAG {"wazuh-manager-remoted:endpoints"};

        const LogFn& logFn()
        {
            static const LogFn instance {LogFn {CACERTS_LOGTAG}.compose("cacerts")};
            return instance;
        }

        // One throttle per cause, so a missing file and a mismatched CA each get their own line
        // per window instead of the second cause hiding behind the first's silence.
        remoted::common::LogThrottle& notFoundThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& caMismatchThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::http::HttpResponse pemResponse(std::string pem)
        {
            remoted::http::HttpResponse response;
            response.status = 200;
            response.body = std::move(pem);
            response.headers.emplace_back("Content-Type", PEM_CONTENT_TYPE);
            return response;
        }
    } // namespace

    remoted::http::RouteHandler makeHandler(std::function<remoted::http::CaCertificateSnapshot()> snapshotOf,
                                            CacertsMetrics metrics,
                                            const remoted::metrics::EndpointHttpMetrics* httpMetrics)
    {
        return [snapshotOf = std::move(snapshotOf), metrics = std::move(metrics), httpMetrics](
                   std::shared_ptr<const remoted::http::HttpRequest> /*request*/,
                   std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // Wrapped once so every answer below lands in remoted.http.cacerts.responses.* (the
            // WHAT); the counters in `metrics` are the WHY. The request itself is irrelevant: no
            // body, no header (an Authorization header, if any, is ignored -- there is nothing to
            // verify it against on a trust-bootstrap route) and the target was already routed.
            if (httpMetrics != nullptr)
            {
                responder = std::make_shared<remoted::metrics::MeteredResponder>(std::move(responder), *httpMetrics);
            }

            // One read behind both decisions: the certificates to publish and the verdict about
            // them cannot disagree, because they came out of the same bytes.
            auto snapshot = snapshotOf ? snapshotOf() : remoted::http::CaCertificateSnapshot {};

            if (snapshot.certificates == 0 || snapshot.pem.empty())
            {
                incNotFound(metrics);
                if (const auto throttle = notFoundThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "GET /cacerts answered 404 to %llu request(s) in the last %d s: the configured CA "
                               "certificate is missing, unreadable, too large or carries no usable certificate; "
                               "agents cannot bootstrap trust from this manager until it is restored.",
                               static_cast<unsigned long long>(throttle.total),
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(remoted::http::HttpResponse::json(404, R"({"error":"not_found"})"));
                return;
            }

            if (snapshot.matchesLeaf.has_value() && !*snapshot.matchesLeaf)
            {
                incCaMismatch(metrics);
                if (const auto throttle = caMismatchThrottle().record())
                {
                    LOGFN_ERROR(logFn(),
                                "GET /cacerts answered 503 to %llu request(s) in the last %d s: the configured CA "
                                "(%s) does not sign the served certificate, so it is not handed out (agents "
                                "would fail every handshake against this manager with it).",
                                static_cast<unsigned long long>(throttle.total),
                                remoted::common::LogThrottle::kDefaultWindowSeconds,
                                snapshot.subjects.c_str());
                }
                responder->send(remoted::http::HttpResponse::json(503, R"({"error":"ca_mismatch"})"));
                return;
            }

            incServed(metrics);
            responder->send(pemResponse(std::move(snapshot.pem)));
        };
    }

} // namespace remoted::endpoints::cacerts
