/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "metricsEndpoint.hpp"

#include <wazuh_metrics/jsonDump.hpp>

#include <utility>

namespace invsync::endpoints::metrics
{

    http::RouteHandler makeHandler(std::weak_ptr<wazuh::metrics::IManager> manager)
    {
        return [weakManager = std::move(manager)](std::shared_ptr<const http::HttpRequest>,
                                                  std::shared_ptr<http::IHttpResponder> responder)
        {
            const auto metricsManager = weakManager.lock();
            if (!metricsManager)
            {
                responder->send(http::HttpResponse::json(503, R"({"error":"Service unavailable","code":503})"));
                return;
            }

            wazuh::metrics::DumpOptions options;
            options.daemonName = "inventory_sync_server";
            responder->send(http::HttpResponse::json(200, wazuh::metrics::dumpJson(*metricsManager, options)));
        };
    }

} // namespace invsync::endpoints::metrics
