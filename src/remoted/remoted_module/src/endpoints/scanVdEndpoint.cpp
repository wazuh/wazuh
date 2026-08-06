/*
 * Wazuh remoted module - VD Scan endpoint
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "scanVdEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"

#include "json.hpp"
#include <charconv>
#include <string>
#include <string_view>
#include <utility>

namespace remoted::endpoints::scanvd
{
    namespace
    {
        constexpr auto SCANVD_ENDPOINT_LOGTAG {"wazuh-manager-remoted:scanvd-endpoint"};

        const LogFn& logFn()
        {
            static const LogFn instance {SCANVD_ENDPOINT_LOGTAG};
            return instance;
        }

        remoted::common::LogThrottle& invalidBodyThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& invalidJsonThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        remoted::common::LogThrottle& invalidAgentIdThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        constexpr std::size_t kMaxScanVdBodySize = 4U * 1024U;

        remoted::http::HttpResponse errorJson(int status, std::string_view code)
        {
            std::string body = R"({"error":")";
            body.append(code);
            body.append(R"("})");
            return remoted::http::HttpResponse::json(status, std::move(body));
        }

        remoted::http::HttpResponse errorJsonWithOffset(int status, std::string_view code, uint64_t currentOffset)
        {
            nlohmann::json response;
            response["error"] = code;
            response["current_version"] = currentOffset;
            return remoted::http::HttpResponse::json(status, response.dump());
        }

        uint32_t parseAgentId(std::string_view agentIdStr)
        {
            uint32_t id = 0;
            auto [ptr, ec] = std::from_chars(agentIdStr.data(), agentIdStr.data() + agentIdStr.size(), id);
            if (ec != std::errc {} || ptr != agentIdStr.data() + agentIdStr.size() || id == 0)
            {
                return 0;
            }
            return id;
        }

    } // namespace

    remoted::endpoints::AuthenticatedHandler makeHandler(ScanVdHandler& handler)
    {
        return [&handler](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                          std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            const auto body = authReq->payload.bytes();
            if (body.empty() || body.size() > kMaxScanVdBodySize)
            {
                if (const auto throttle = invalidBodyThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Invalid /scan/vd body size (agent %.*s): rejected %llu request(s) in the last %d s.",
                               static_cast<int>(authReq->agentId.size()),
                               authReq->agentId.data(),
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "invalid_body"));
                return;
            }

            nlohmann::json json;
            try
            {
                json = nlohmann::json::parse(body);
            }
            catch (const std::exception&)
            {
                if (const auto throttle = invalidJsonThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Invalid JSON in /scan/vd (agent %.*s): rejected %llu request(s) in the last %d s.",
                               static_cast<int>(authReq->agentId.size()),
                               authReq->agentId.data(),
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "invalid_json"));
                return;
            }

            const uint32_t agentId = parseAgentId(authReq->agentId);
            if (agentId == 0)
            {
                if (const auto throttle = invalidAgentIdThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Invalid agent ID in /scan/vd: rejected %llu request(s) in the last %d s.",
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "invalid_agent_id"));
                return;
            }

            if (!json.contains("type") || !json["type"].is_string())
            {
                responder->send(errorJson(400, "missing_type"));
                return;
            }

            const std::string type = json["type"].get<std::string>();
            if (type != "feed_update")
            {
                responder->send(errorJson(400, "invalid_type"));
                return;
            }

            if (!json.contains("feed_offset") || !json["feed_offset"].is_number_unsigned())
            {
                responder->send(errorJson(400, "missing_feed_offset"));
                return;
            }

            const uint64_t requestedOffset = json["feed_offset"].get<uint64_t>();

            handler.handleVdScan(agentId,
                                 requestedOffset,
                                 [responder](const ScanVdResponse& response)
                                 {
                                     switch (response.outcome)
                                     {
                                         case ScanVdOutcome::Accepted:
                                             responder->send(remoted::http::HttpResponse::json(200, "{}"));
                                             break;
                                         case ScanVdOutcome::VersionMismatch:
                                             responder->send(
                                                 errorJsonWithOffset(409, "version_mismatch", response.currentOffset));
                                             break;
                                         case ScanVdOutcome::QueueFull:
                                             // Distinct from version_mismatch: the offset matched, but this
                                             // node's scan tracking table is full. Retrying the same offset
                                             // against a different node (or once capacity frees up here) can
                                             // succeed, unlike a real version mismatch.
                                             responder->send(errorJson(503, "scan_queue_full"));
                                             break;
                                         case ScanVdOutcome::InvalidAgent:
                                             responder->send(errorJson(400, "invalid_agent_id"));
                                             break;
                                     }
                                 });
        };
    }

} // namespace remoted::endpoints::scanvd
