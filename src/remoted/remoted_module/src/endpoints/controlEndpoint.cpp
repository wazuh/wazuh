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

#include "control/controlTypes.hpp" // AgentId, StartupData, NotifyData, ShutdownData, HostInfo, HttpResponse

#include "json.hpp"
#include <charconv>
#include <string>
#include <string_view>
#include <utility>

namespace remoted::endpoints::control
{
    namespace
    {
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
                responder->send(errorJson(400, "invalid_body"));
                return;
            }

            // Length-based parse: the payload is a string_view into a shared,
            // non-null-terminated transport buffer. Any parse failure collapses
            // to a neutral 400 with no leaked parser detail.
            nlohmann::json j = nlohmann::json::parse(body.data(), body.data() + body.size(), nullptr, false);
            if (j.is_discarded() || !j.is_object())
            {
                responder->send(errorJson(400, "invalid_json"));
                return;
            }

            remoted::control::AgentId id = 0;
            if (!parseAgentId(authReq->agentId, id))
            {
                responder->send(errorJson(400, "invalid_agent_id"));
                return;
            }

            const std::string type = readString(j, "type");
            if (type == "startup")
            {
                remoted::control::StartupData data;
                data.version = readString(j, "version");
                handler.handleStartup(id, data, bridgeToResponder(std::move(responder)));
            }
            else if (type == "notify")
            {
                remoted::control::NotifyData data = parseNotify(j);
                handler.handleNotify(id, data, bridgeToResponder(std::move(responder)));
            }
            else if (type == "shutdown")
            {
                handler.handleShutdown(id, remoted::control::ShutdownData {}, bridgeToResponder(std::move(responder)));
            }
            else
            {
                responder->send(errorJson(400, "unknown_message_type"));
            }
        };
    }

} // namespace remoted::endpoints::control
