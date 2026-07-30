/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "statelessEndpoint.hpp"

#include <rapidjson/document.h>
#include <rapidjson/pointer.h>

#include <charconv>
#include <optional>
#include <string_view>
#include <utility>

namespace remoted::endpoints::stateless
{

    remoted::downstream::DownstreamTarget target(const std::string& socketPath)
    {
        remoted::downstream::DownstreamTarget result {
            socketPath, remoted::http::Method::Post, "/events/enriched", "application/x-ndjson"};
        result.serviceName = "engine event ingress";
        return result;
    }

    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response)
    {
        using remoted::downstream::DownstreamError;
        using remoted::http::HttpResponse;

        if (error != DownstreamError::None)
        {
            // Could not reach the engine / no timely answer -> the agent retries.
            return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
        }

        const int status = response.status;
        if (status >= 200 && status < 300)
        {
            // The engine accepted/enqueued the batch (it does not fully process it here).
            return HttpResponse {202, "", {}};
        }
        if (status == 400)
        {
            return HttpResponse::json(400, R"({"error":"Invalid event batch","code":400})");
        }
        if (status == 413)
        {
            return HttpResponse::json(413, R"({"error":"Request payload is too large","code":413})");
        }
        // 5xx / unexpected -> treat as a transient server-side failure.
        return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }

    namespace
    {
        // H-line is metadata (agent id, name, cluster labels, ...), never bulk event data -- a real
        // one is realistically a few hundred bytes. Capped well before parsing so a pathologically
        // large/nested JSON blob (still comfortably inside the 10 MiB body cap) is rejected outright
        // instead of costing CPU/heap proportional to its size.
        constexpr std::size_t kMaxHeaderLineJsonSize = 8U * 1024U;

        // Slices the H-line's JSON substring out of the whole H/E body. Per the event-protocol's own
        // parsing rule ("split by \n, check first char, extract payload after space (index 2)"): the
        // body must start with the two literal characters 'H',' '; the JSON runs to the first '\n'
        // (or to the end of the body if there is none -- e.g. a header-only body with no events).
        std::optional<std::string_view> headerLineJson(std::string_view body)
        {
            constexpr std::string_view kPrefix = "H ";
            if (body.size() < kPrefix.size() || body.substr(0, kPrefix.size()) != kPrefix)
            {
                return std::nullopt;
            }
            const std::string_view rest = body.substr(kPrefix.size());
            const auto newline = rest.find('\n');
            const std::string_view result = newline == std::string_view::npos ? rest : rest.substr(0, newline);
            if (result.size() > kMaxHeaderLineJsonSize)
            {
                return std::nullopt;
            }
            return result;
        }

        // Non-negative integer, fully consuming the string. from_chars<AgentId> (unsigned) already
        // rejects a leading '-'; checking ptr against the end also rejects a partial match (e.g. "12x").
        std::optional<remoted::auth::AgentId> parseAgentId(std::string_view s)
        {
            remoted::auth::AgentId value = 0;
            const auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), value);
            if (s.empty() || ec != std::errc {} || ptr != s.data() + s.size())
            {
                return std::nullopt;
            }
            return value;
        }

        std::optional<std::string_view> getString(const rapidjson::Document& doc, const rapidjson::Pointer& pointer)
        {
            const auto* value = pointer.Get(doc);
            if (!value || !value->IsString())
            {
                return std::nullopt;
            }
            return std::string_view {value->GetString(), value->GetStringLength()};
        }
    } // namespace

    remoted::auth::AuthError validatePayloadIdentity(const remoted::auth::AuthenticatedRequest& req)
    {
        using remoted::auth::AuthError;
        static const rapidjson::Pointer kAgentIdPointer("/wazuh/agent/id");

        const auto headerJson = headerLineJson(req.payload.bytes());
        if (!headerJson)
        {
            return AuthError::PayloadAgentMismatch;
        }

        rapidjson::Document doc;
        // Length-based, non-in-situ parse: the payload is a string_view into a shared buffer that is
        // neither mutable nor NUL-terminated, so it cannot be parsed in place or as a C-string.
        // kParseIterativeFlag: bounds the parser's C-stack usage to a constant regardless of input
        // nesting depth (it uses an explicit heap stack instead of recursive descent) -- without it,
        // a deeply-nested H-line (still well inside kMaxHeaderLineJsonSize) could overflow this
        // worker thread's stack. Only changes how the DOM is built, not its shape: Pointer::Get()
        // below is unaffected.
        doc.Parse<rapidjson::kParseIterativeFlag>(headerJson->data(), headerJson->size());
        if (doc.HasParseError())
        {
            return AuthError::PayloadAgentMismatch;
        }

        const auto payloadAgentIdStr = getString(doc, kAgentIdPointer);
        if (!payloadAgentIdStr)
        {
            return AuthError::PayloadAgentMismatch;
        }

        const auto payloadAgentId = parseAgentId(*payloadAgentIdStr);
        const auto authenticatedAgentId = parseAgentId(req.agentId);
        if (!payloadAgentId || !authenticatedAgentId || *payloadAgentId != *authenticatedAgentId)
        {
            return AuthError::PayloadAgentMismatch;
        }

        return AuthError::None;
    }

    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                                                         std::string socketPath)
    {
        return [&forwarder,
                socketPath = std::move(socketPath)](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                                    std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            const auto err = validatePayloadIdentity(*authReq);
            if (err != remoted::auth::AuthError::None)
            {
                // Pass the authenticated agent id: this rejection happens AFTER the MAC verified, so
                // naming the agent that signed the request is what makes the resulting warning
                // actionable (see errorResponseFor()).
                responder->send(remoted::endpoints::errorResponseFor(err, authReq->agentId));
                return;
            }
            forwarder.forward(std::move(authReq), std::move(responder), target(socketPath), postProcess);
        };
    }

} // namespace remoted::endpoints::stateless
