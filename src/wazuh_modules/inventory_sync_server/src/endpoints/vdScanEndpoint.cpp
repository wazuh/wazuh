/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "vdScanEndpoint.hpp"

#include "common/agentId.hpp"
#include "loggerHelper.h"

#include <cstdint>
#include <json.hpp>
#include <optional>
#include <string>
#include <utility>

namespace
{
    constexpr auto VD_SCAN_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    const LogFn& logFn()
    {
        static const LogFn instance {VD_SCAN_LOGTAG};
        return instance;
    }

    wazuh::uds_http::HttpResponse errorResponse(int status, const std::string& reason)
    {
        // Built as JSON, not concatenated, so a reason holding quotes still yields a valid body. Ordered to
        // keep the documented {"error":...,"code":...} shape.
        return wazuh::uds_http::HttpResponse::json(status,
                                                   nlohmann::ordered_json {{"error", reason}, {"code", status}}.dump());
    }

    /// The in-flight interlock's answer. `retryable` is redundant against a 409 -- the dispatcher
    /// already reads that status as "busy" whatever the body says -- but it states the intent on
    /// the wire for anything else that ever reads a capture of it.
    constexpr auto SCAN_IN_PROGRESS_BODY {R"({"error":"scan_in_progress","code":409,"retryable":true})"};

    /// What the request body asks for.
    struct ScanRequest
    {
        std::string agentId;    ///< Canonical spelling ("7" and "0007" -> "007").
        bool firstScan {false}; ///< The agent's first scan, which indexes without alerting.
    };

    /**
     * @brief Read the request body: the target agent id and the optional `first_scan` flag.
     *
     * The body, and only the body: the dispatcher POSTs a task row's PAYLOAD verbatim and adds no
     * headers of its own. Identical contract to the deletion route's for "which agent",
     * deliberately -- both are driven by the same caller, and one shape is one fewer thing for a
     * producer to get wrong. Parsed ONCE, for both members: this runs inline on an I/O thread.
     *
     * Not authenticated remote input: this route is UDS-local (D15) and its caller is another
     * manager daemon, so this guards against a caller bug, not against spoofing.
     *
     * @param[out] reason Caller-facing 400 message, set only on failure.
     * @return The request, or nullopt when `agent_id` is absent or not an agent id (not digits, or
     *         out of the 32-bit range), or `first_scan` is present and not a JSON boolean.
     */
    std::optional<ScanRequest> parseScanRequest(const wazuh::uds_http::HttpRequest& request, const char*& reason)
    {
        // Non-throwing parse, like every other body-reading route here: a malformed body is
        // ordinary input, and letting nlohmann throw would cost an exception per bad request. A
        // discarded value is not an object, so the one check covers both.
        const auto document = nlohmann::json::parse(request.body, nullptr, /*allow_exceptions=*/false);
        if (!document.is_object())
        {
            reason = R"(Body must be a JSON object with an "agent_id" member)";
            return std::nullopt;
        }

        const auto agentIdIt = document.find("agent_id");
        if (agentIdIt == document.end())
        {
            reason = R"(Body must carry an "agent_id" member)";
            return std::nullopt;
        }

        // Both JSON spellings of a small integer are accepted, for the same reason the deletion
        // route accepts them: a producer that emits 7 instead of "7" should not be rejected over
        // its choice of spelling.
        std::string agentId;
        if (agentIdIt->is_string())
        {
            agentId = agentIdIt->get<std::string>();
        }
        else if (agentIdIt->is_number_unsigned())
        {
            agentId = std::to_string(agentIdIt->get<std::uint64_t>());
        }

        auto canonical = invsync::common::canonicalAgentId(agentId);
        if (!canonical)
        {
            reason = R"("agent_id" must be a numeric agent id)";
            return std::nullopt;
        }

        ScanRequest parsed;
        parsed.agentId = std::move(*canonical);

        // Absent is false. Any value but a JSON boolean is refused rather than read as one, since
        // mistaking it for true would hide every alert of that scan.
        if (const auto firstScanIt = document.find("first_scan"); firstScanIt != document.end())
        {
            if (!firstScanIt->is_boolean())
            {
                reason = R"("first_scan" must be a boolean)";
                return std::nullopt;
            }
            parsed.firstScan = firstScanIt->get<bool>();
        }

        return parsed;
    }
} // namespace

namespace invsync::endpoints::vd_scan
{

    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies)
    {
        return [deps = std::move(dependencies)](std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                                                std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
        {
            if (!request)
            {
                // Counted here, the site that sends it. The terminal response is the lane's to
                // count, so a request is never counted twice (Dependencies).
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Empty request"));
                return;
            }

            const char* rejectionReason = nullptr;
            const auto scanRequest = parseScanRequest(*request, rejectionReason);
            if (!scanRequest)
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, rejectionReason));
                return;
            }

            const auto lane = deps.scanLane.lock();
            if (!lane)
            {
                // The facade's teardown has already dropped the lane: the module is stopping.
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            invsync::vd::VdScanLane::Item item;
            item.request = request;
            // The responder rides along, and that is the whole contract: the lane's own worker
            // answers with the scan's outcome, which is what lets a task row read `completed` and
            // mean scanned rather than "accepted".
            item.responder = responder;
            item.kind = invsync::sync::SyncPipeline::Item::Kind::VdScanRequest;
            item.firstScan = scanRequest->firstScan;
            // Canonical like every document `_id`, query and registry key. That one spelling is what
            // makes the per-agent exclusion work ACROSS the two lanes: the pipeline registers an
            // agent's sessions under this form, so a scan keyed on the raw id would be invisible to
            // it and could run while that agent's session is mid-apply.
            const auto& agentId = scanRequest->agentId;
            item.session.agentId = agentId;

            switch (lane->tryEnqueue(std::move(item)))
            {
                case invsync::vd::VdScanLane::Admission::Accepted:
                    // Nothing sent and nothing counted: the responder is on the item now and the
                    // lane will answer through it. DEBUG rather than INFO because the lane already
                    // logs every outcome, and a second per-request line would only say it started.
                    LOGFN_DEBUG1(logFn(), "On-demand vulnerability scan of agent %s queued.", agentId.c_str());
                    return;

                case invsync::vd::VdScanLane::Admission::AgentBusy:
                    // THE interlock this route needs, and the reason it is worth its own status. A
                    // client-side timeout does not cancel server-side work: the dispatcher gives up
                    // at 300 s and re-posts, while the first scan is very likely still running.
                    // Without this the second request would either park until the transport's
                    // backstop fired, or start a concurrent scan of the same agent.
                    //
                    // 409 rather than 503, because the dispatcher tells them apart: a 409 defers
                    // without consuming an attempt, which is right -- being busy is not a failure.
                    LOGFN_DEBUG1(logFn(),
                                 "On-demand vulnerability scan of agent %s refused: a scan of that agent is already "
                                 "in flight.",
                                 agentId.c_str());
                    deps.requestCounters.count(409);
                    responder->send(wazuh::uds_http::HttpResponse::json(409, SCAN_IN_PROGRESS_BODY));
                    return;

                case invsync::vd::VdScanLane::Admission::Full:
                    // The lane's bounded queue IS this route's capacity control, which is what
                    // RouteClass::Control requires of a route that does real work. The lane counts
                    // the refusal itself (vd.capacity.503); this counts the response.
                    deps.requestCounters.count(503);
                    responder->send(errorResponse(503, "scan capacity exhausted"));
                    return;

                case invsync::vd::VdScanLane::Admission::Stopping:
                default:
                    deps.requestCounters.count(503);
                    responder->send(errorResponse(503, "Service unavailable"));
                    return;
            }
        };
    }

} // namespace invsync::endpoints::vd_scan
