/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "configEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"
#include "timeHelper.h"

#include <exception>
#include <json.hpp>
#include <string>
#include <utility>

namespace
{
    constexpr auto CONFIG_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // One shared instance rather than a per-call temporary: this runs on EVERY request.
    // loggerHelper.h stays out of configEndpoint.hpp, which the tests include.
    const LogFn& logFn()
    {
        static const LogFn instance {CONFIG_ENDPOINT_LOGTAG};
        return instance;
    }

    invsync::http::HttpResponse badRequest(const char* reason)
    {
        return invsync::http::HttpResponse::json(400, std::string {R"({"error":")"} + reason + R"(","code":400})");
    }
} // namespace

namespace invsync::endpoints::config
{

    http::RouteHandler makeHandler()
    {
        return [](std::shared_ptr<const http::HttpRequest> request, std::shared_ptr<http::IHttpResponder> responder)
        {
            // Throttled and function-local: how often this fires is driven by how often agents report,
            // so one line per request would be a log-amplification vector against wazuh-manager.log.
            static invsync::common::LogThrottle acceptedThrottle;

            if (!request)
            {
                responder->send(badRequest("Empty request"));
                return;
            }

            // remoted sets this from the identity it authenticated. Its absence means the request did
            // not come through remoted's authenticated route, so it is a contract violation, not agent
            // input -- hence a flat 400 rather than anything more specific.
            const auto agentIdIt = request->headers.find(agentIdHeader());
            if (agentIdIt == request->headers.end() || agentIdIt->second.empty())
            {
                responder->send(badRequest("Missing agent id header"));
                return;
            }

            // Non-throwing parse: a malformed document is ordinary input here, not an error condition,
            // and letting nlohmann throw would cost an exception per bad request.
            auto document = nlohmann::json::parse(request->body, nullptr, /*allow_exceptions=*/false);
            if (document.is_discarded() || !document.is_object())
            {
                responder->send(badRequest("Body must be a JSON object"));
                return;
            }

            try
            {
                // JSON pointers rather than bracket chaining, so `wazuh.agent.id` reads the same way
                // it is spelled everywhere else in the schema. Both overwrite whatever the agent sent:
                // the authenticated id and the server's clock are the authoritative ones.
                document["/wazuh/agent/id"_json_pointer] = agentIdIt->second;
                document["/@timestamp"_json_pointer] = Utils::getCurrentISO8601();

                if (const auto decision = acceptedThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Enriched and discarded %llu config document(s) in the last %d s. This endpoint is a "
                                 "dummy: the document is echoed back but not stored.",
                                 static_cast<unsigned long long>(decision.total),
                                 invsync::common::LogThrottle::kDefaultWindowSeconds);
                }

                // Echoed back so the caller can see what was added; the document itself is dropped.
                responder->send(http::HttpResponse::json(200, document.dump()));
            }
            catch (const std::exception& e)
            {
                // Serializing back out can still fail on input we accepted -- e.g. a string field
                // holding invalid UTF-8, which nlohmann rejects at dump() time, not at parse time.
                LOGFN_DEBUG1(logFn(), "Could not serialize an enriched config document: %s.", e.what());
                responder->send(badRequest("Body must be a JSON object"));
            }
        };
    }

} // namespace invsync::endpoints::config
