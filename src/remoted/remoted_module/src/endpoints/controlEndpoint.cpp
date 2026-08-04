/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "controlEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "control/controlTypes.hpp" // AgentId, StartupData, NotifyData, ShutdownData, HostInfo, HttpResponse
#include "loggerHelper.h"

#include "json.hpp"
#include <charconv>
#include <string>
#include <string_view>
#include <utility>

namespace remoted::endpoints::control
{
    namespace
    {
        constexpr auto CONTROL_ENDPOINT_LOGTAG {"wazuh-manager-remoted:control-endpoint"};

        // One shared instance to avoid heap allocations per log call (LogFn holds a std::string
        // and this tag is past the SSO threshold). Kept in .cpp to avoid pulling loggerHelper.h
        // into the header (see auth/keystore.cpp for the reason).
        const LogFn& logFn()
        {
            static const LogFn instance {CONTROL_ENDPOINT_LOGTAG};
            return instance;
        }

        // Throttles for recurring errors to avoid log flooding. Each condition gets its own throttle
        // so different error types can be reported independently.
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

        remoted::common::LogThrottle& unknownTypeThrottle()
        {
            static remoted::common::LogThrottle instance;
            return instance;
        }

        // Cap on the /control JSON body actually parsed. The transport already
        // enforces a hard body cap; this is a second, endpoint-local guard so a
        // pathological JSON blob (still under the transport cap) can't cost
        // parse-time CPU / heap proportional to its size.
        constexpr std::size_t kMaxControlBodySize = 64U * 1024U;

        remoted::http::HttpResponse errorJson(int status, std::string_view code)
        {
            std::string body = R"({"error":")";
            body.append(code);
            body.append(R"("})");
            return remoted::http::HttpResponse::json(status, std::move(body));
        }

        // Non-negative integer, fully consuming the string. Rejects a leading '-'
        // (from_chars<uint32_t> already does) and any trailing garbage. Same
        // policy stateless uses for its own agent-id parse.
        bool parseAgentId(std::string_view s, remoted::control::AgentId& out)
        {
            remoted::control::AgentId value = 0;
            const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
            if (s.empty() || ec != std::errc {} || ptr != s.data() + s.size())
            {
                return false;
            }
            out = value;
            return true;
        }

        // Robust string field: returns "" on missing / non-string. nlohmann::json
        // is strict on wrong types via .get<std::string>(); .value() catches only
        // missing keys. We want both to collapse to empty and let the underlying
        // ControlHandler validate.
        std::string readString(const nlohmann::json& obj, const char* key)
        {
            if (auto it = obj.find(key); it != obj.end() && it->is_string())
            {
                return it->get<std::string>();
            }
            return {};
        }

        remoted::control::NotifyData parseNotify(const nlohmann::json& j)
        {
            remoted::control::NotifyData data;

            if (auto agentIt = j.find("agent"); agentIt != j.end() && agentIt->is_object())
            {
                data.version = readString(*agentIt, "version");
            }

            if (auto hostIt = j.find("host"); hostIt != j.end() && hostIt->is_object())
            {
                remoted::control::HostInfo host;
                host.hostname = readString(*hostIt, "hostname");
                host.architecture = readString(*hostIt, "architecture");
                host.ip = readString(*hostIt, "ip");

                if (auto osIt = hostIt->find("os"); osIt != hostIt->end() && osIt->is_object())
                {
                    host.osName = readString(*osIt, "name");
                    host.osVersion = readString(*osIt, "version");
                    host.osPlatform = readString(*osIt, "platform");
                    host.osType = readString(*osIt, "type");
                }
                data.host = std::move(host);
            }

            return data;
        }

        // Bridges the control-layer HttpResponse ({status, body}) to the transport
        // HttpResponse (status + body + headers). All /control responses are JSON;
        // ControlHandler builds a JSON body for every reply (including "{}" for
        // shutdown), so Content-Type is set unconditionally.
        remoted::control::ResponseCallback bridgeToResponder(std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            return [responder = std::move(responder)](const remoted::control::HttpResponse& r)
            {
                responder->send(remoted::http::HttpResponse::json(r.status, r.body));
            };
        }
    } // namespace

    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::control::ControlHandler& handler)
    {
        return [&handler](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                          std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            const auto body = authReq->payload.bytes();
            if (body.empty() || body.size() > kMaxControlBodySize)
            {
                // Throttle to avoid flooding on repeated malformed requests
                if (const auto throttle = invalidBodyThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Invalid /control body size (agent %.*s): rejected %llu request(s) in the last %d s.",
                               static_cast<int>(authReq->agentId.size()),
                               authReq->agentId.data(),
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "invalid_body"));
                return;
            }

            // Length-based parse: the payload is a string_view into a shared,
            // non-null-terminated transport buffer. Any parse failure collapses
            // to a neutral 400 with no leaked parser detail.
            nlohmann::json j = nlohmann::json::parse(body.data(), body.data() + body.size(), nullptr, false);
            if (j.is_discarded() || !j.is_object())
            {
                if (const auto throttle = invalidJsonThrottle().record())
                {
                    LOGFN_WARN(logFn(),
                               "Invalid /control JSON (agent %.*s): rejected %llu request(s) in the last %d s.",
                               static_cast<int>(authReq->agentId.size()),
                               authReq->agentId.data(),
                               throttle.total,
                               remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "invalid_json"));
                return;
            }

            remoted::control::AgentId id = 0;
            if (!parseAgentId(authReq->agentId, id))
            {
                if (const auto throttle = invalidAgentIdThrottle().record())
                {
                    LOGFN_WARN(
                        logFn(),
                        "Invalid agent ID in /control request (%.*s): rejected %llu request(s) in the last %d s.",
                        static_cast<int>(authReq->agentId.size()),
                        authReq->agentId.data(),
                        throttle.total,
                        remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "invalid_agent_id"));
                return;
            }

            const std::string type = readString(j, "type");
            if (type == "startup")
            {
                remoted::control::StartupData data;
                data.version = readString(j, "version");
                LOGFN_DEBUG1(logFn(), "Agent %u: /control startup (version=%s).", id, data.version.c_str());
                handler.handleStartup(id, data, bridgeToResponder(std::move(responder)));
            }
            else if (type == "notify")
            {
                remoted::control::NotifyData data = parseNotify(j);
                // DEBUG2 because notify is the hot path (periodic keepalives)
                LOGFN_DEBUG2(logFn(), "Agent %u: /control notify.", id);
                handler.handleNotify(id, data, bridgeToResponder(std::move(responder)));
            }
            else if (type == "shutdown")
            {
                LOGFN_DEBUG1(logFn(), "Agent %u: /control shutdown.", id);
                handler.handleShutdown(id, remoted::control::ShutdownData {}, bridgeToResponder(std::move(responder)));
            }
            else
            {
                if (const auto throttle = unknownTypeThrottle().record())
                {
                    LOGFN_WARN(
                        logFn(),
                        "Unknown /control message type '%s' (agent %u): rejected %llu request(s) in the last %d s.",
                        type.c_str(),
                        id,
                        throttle.total,
                        remoted::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(errorJson(400, "unknown_message_type"));
            }
        };
    }

} // namespace remoted::endpoints::control
