/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syncEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"

#include <utility>

namespace
{
    constexpr auto SYNC_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // One shared instance rather than a per-call temporary: this runs on EVERY request.
    // loggerHelper.h stays out of syncEndpoint.hpp, which the tests include.
    const LogFn& logFn()
    {
        static const LogFn instance {SYNC_ENDPOINT_LOGTAG};
        return instance;
    }
} // namespace

namespace invsync::endpoints::sync
{

    http::RouteHandler makeHandler()
    {
        return [](std::shared_ptr<const http::HttpRequest> request, std::shared_ptr<http::IHttpResponder> responder)
        {
            // Throttled, and function-local because there is no object to hang it off: an
            // unauthenticated peer controls how often this fires, so one line per request would be a
            // log-amplification vector against wazuh-manager.log.
            static invsync::common::LogThrottle acceptedThrottle;

            const auto bodySize = request ? request->body.size() : 0U;

            if (const auto decision = acceptedThrottle.record())
            {
                LOGFN_DEBUG1(logFn(),
                             "Accepted and discarded %llu inventory sync request(s) in the last %d s (last one was "
                             "%zu byte(s)). This endpoint is a stub: the payload is not decoded or stored yet.",
                             static_cast<unsigned long long>(decision.total),
                             invsync::common::LogThrottle::kDefaultWindowSeconds,
                             bodySize);
            }

            // Answer inline and drop the payload. 202 rather than 200 on purpose: it is the status
            // the real endpoint will return once the payload is queued rather than processed, so the
            // peer's own result mapping does not have to change when the pipeline lands.
            responder->send(http::HttpResponse::json(202, R"({"status":"accepted"})"));
        };
    }

} // namespace invsync::endpoints::sync
