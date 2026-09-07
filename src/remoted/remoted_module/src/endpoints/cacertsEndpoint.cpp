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

#include <fstream>
#include <iterator>
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

        /// The marker every servable file must carry: a PEM with no certificate block (an empty
        /// file, a key, garbage) is "not found" -- there is nothing an agent could trust in it.
        constexpr std::string_view PEM_CERTIFICATE_HEADER {"-----BEGIN CERTIFICATE-----"};

        /// Reads the whole file; false when it cannot be opened. Same primitive the transport uses
        /// to pre-check its own cert/key (checkTlsFileReadable), which is why an unreadable CA is
        /// a warning at start rather than a fatal error: the listener still serves everything else.
        bool readFile(const std::string& path, std::string& contents)
        {
            std::ifstream file {path, std::ios::binary};
            if (!file.is_open())
            {
                return false;
            }
            contents.assign(std::istreambuf_iterator<char> {file}, std::istreambuf_iterator<char> {});
            return true;
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

    remoted::http::RouteHandler makeHandler(std::string caCertificatePath,
                                            std::function<remoted::http::TlsCertificateSnapshot()> status,
                                            CacertsMetrics metrics,
                                            const remoted::metrics::EndpointHttpMetrics* httpMetrics)
    {
        return [caCertificatePath = std::move(caCertificatePath),
                status = std::move(status),
                metrics = std::move(metrics),
                httpMetrics](std::shared_ptr<const remoted::http::HttpRequest> /*request*/,
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

            std::string pem;
            if (!readFile(caCertificatePath, pem) || pem.find(PEM_CERTIFICATE_HEADER) == std::string::npos)
            {
                incNotFound(metrics);
                if (const auto throttle = notFoundThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "GET /cacerts answered 404 to %llu request(s) in the last %d s: the CA certificate "
                               "'%s' is missing, unreadable or carries no certificate; agents cannot bootstrap "
                               "trust from this manager until it is restored.",
                               static_cast<unsigned long long>(throttle.total),
                               remoted::common::LogThrottle::kDefaultWindowSeconds,
                               caCertificatePath.c_str());
                }
                responder->send(remoted::http::HttpResponse::json(404, R"({"error":"not_found"})"));
                return;
            }

            // Only an explicit "does not sign" refuses. Unknown (never evaluated, or the file was
            // unreadable at the last tick and has since been restored) serves: refusing there
            // would turn a transient read failure into a 24 h outage of the trust bootstrap.
            const auto snapshot = status ? status() : remoted::http::TlsCertificateSnapshot {};
            if (snapshot.caMatchesLeaf.has_value() && !*snapshot.caMatchesLeaf)
            {
                incCaMismatch(metrics);
                if (const auto throttle = caMismatchThrottle().record())
                {
                    LOGFN_ERROR(logFn(),
                                "GET /cacerts answered 503 to %llu request(s) in the last %d s: the configured CA "
                                "'%s' does not sign the served certificate, so it is not handed out (agents "
                                "would fail every handshake against this manager with it).",
                                static_cast<unsigned long long>(throttle.total),
                                remoted::common::LogThrottle::kDefaultWindowSeconds,
                                caCertificatePath.c_str());
                }
                responder->send(remoted::http::HttpResponse::json(503, R"({"error":"ca_mismatch"})"));
                return;
            }

            incServed(metrics);
            responder->send(pemResponse(std::move(pem)));
        };
    }

} // namespace remoted::endpoints::cacerts
