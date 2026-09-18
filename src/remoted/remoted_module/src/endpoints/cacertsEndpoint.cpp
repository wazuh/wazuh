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
#include "http_server/caCertificateSource.hpp"
#include "http_server/fileRead.hpp"

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

        // One throttle per cause, so a missing file, a mismatched CA and a read failure each get
        // their own line per window instead of one cause hiding behind another's silence. Owned by
        // the handler -- one per route registration -- rather than by the process: a restart starts
        // its windows afresh, and two handlers alive in one process (two servers in a test binary)
        // never take each other's line.
        struct Throttles
        {
            remoted::common::LogThrottle notFound;
            remoted::common::LogThrottle caMismatch;
            remoted::common::LogThrottle readFailure;
        };

        std::string causeOf(const remoted::http::ReadFailure& failure)
        {
            return remoted::http::describeReadFailure(failure, remoted::http::CaCertificateSource::kMaxBytes);
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

    remoted::http::HttpResponse rateLimitedResponse()
    {
        return remoted::http::HttpResponse::json(429, R"({"error":"rate_limited"})");
    }

    remoted::http::RouteHandler makeHandler(std::function<remoted::http::CaCertificateSnapshot()> snapshotOf,
                                            CacertsMetrics metrics,
                                            const remoted::metrics::EndpointHttpMetrics* httpMetrics,
                                            std::function<void()> deliverCaRecordEvents)
    {
        auto throttles = std::make_shared<Throttles>();
        return [snapshotOf = std::move(snapshotOf),
                metrics = std::move(metrics),
                httpMetrics,
                throttles,
                deliverCaRecordEvents =
                    std::move(deliverCaRecordEvents)](std::shared_ptr<const remoted::http::HttpRequest> /*request*/,
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

            // Before ANY of the three answers below, never after: whatever that read noticed about
            // the bundle's publication is logged and persisted here (issue #39319). It runs on the
            // 404 and 503 paths too -- a bundle that stopped being servable, or one no CA signs, is
            // exactly when an operator needs the publication line -- and it takes no lock of the
            // source, so it cannot deadlock against the read above.
            if (deliverCaRecordEvents)
            {
                deliverCaRecordEvents();
            }

            if (snapshot.certificates == 0 || snapshot.pem.empty())
            {
                incNotFound(metrics);
                if (const auto throttle = throttles->notFound.record())
                {
                    if (snapshot.lastReadFailure.has_value())
                    {
                        // Nothing was ever served from this file and it cannot be read now: name the
                        // cause, because a missing file, a directory at the path and an oversized file
                        // lead the operator to different fixes.
                        LOGFN_WARN(logFn(),
                                   "GET /cacerts answered 404 to %llu request(s) in the last %d s: the configured CA "
                                   "certificate %s (%llu consecutive failed read(s)); agents cannot bootstrap trust "
                                   "from this manager until it is restored.",
                                   static_cast<unsigned long long>(throttle.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds,
                                   causeOf(*snapshot.lastReadFailure).c_str(),
                                   static_cast<unsigned long long>(snapshot.lastReadFailure->consecutive));
                    }
                    else
                    {
                        LOGFN_WARN(logFn(),
                                   "GET /cacerts answered 404 to %llu request(s) in the last %d s: the configured CA "
                                   "certificate carries no usable certificate; agents cannot bootstrap trust from "
                                   "this manager until it is restored.",
                                   static_cast<unsigned long long>(throttle.total),
                                   remoted::common::LogThrottle::kDefaultWindowSeconds);
                    }
                }
                responder->send(remoted::http::HttpResponse::json(404, R"({"error":"not_found"})"));
                return;
            }

            if (snapshot.lastReadFailure.has_value())
            {
                // The source kept the last good bundle through a read that failed (issue #39318):
                // answer from it -- 200 or 503, exactly as that bundle deserves -- and say so, once
                // per window, so the operator learns about the file before the agents do.
                if (const auto throttle = throttles->readFailure.record())
                {
                    LOGFN_WARN(logFn(),
                               "GET /cacerts is answering %llu request(s) in the last %d s from the last good read of "
                               "the configured CA certificate, which now %s (%llu consecutive failed read(s)); "
                               "restore the file -- the bundle being served predates the failure.",
                               static_cast<unsigned long long>(throttle.total),
                               remoted::common::LogThrottle::kDefaultWindowSeconds,
                               causeOf(*snapshot.lastReadFailure).c_str(),
                               static_cast<unsigned long long>(snapshot.lastReadFailure->consecutive));
                }
            }

            if (snapshot.matchesLeaf.has_value() && !*snapshot.matchesLeaf)
            {
                incCaMismatch(metrics);
                if (const auto throttle = throttles->caMismatch.record())
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
