/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_VD_SCAN_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_VD_SCAN_ENDPOINT_HPP

#include "common/metricNames.hpp" // invsync::metrics::RequestCounters
#include "vd/vdScanLane.hpp"
#include <uds_http_server/IUdsHttpServer.hpp>

#include <cstddef>
#include <memory>

namespace invsync::endpoints::vd_scan
{

    /**
     * @brief On-demand vulnerability rescan of one agent: `POST /_internal/vd/scan`.
     *
     * UDS-local only (D15) and manager-internal: the sole caller is the Task Manager's dispatcher,
     * executing a durable `vd_scan` row that the vulnerability scanner's admission route created
     * when an agent noticed the feed offset had moved.
     *
     * WHY THIS ROUTE LIVES HERE and not in the vulnerability scanner, which owns the scan itself:
     *
     *  - `AgentInFlightRegistry` is private to this module's `src/vd/`, and the seam the scanner
     *    exports offers pause/quiesce, not membership. A scan started outside this module would be
     *    invisible to the pipeline, so it could run while a session of that same agent is mid-apply
     *    -- the delete-then-reindex ordering D22 exists to protect.
     *  - `VdScanLane` already IS what an execution route would have to build: a bounded admission
     *    queue, per-agent exclusion, a responder held to completion, 503 on capacity and a
     *    feed-readiness re-check at dispatch. A second copy would not be duplicated effort, it
     *    would be a race.
     *
     * ANSWERED AT COMPLETION. The dispatcher writes its task row `completed` on the 200, so the
     * item carries its responder onto the lane and the lane's own worker answers with the scan's
     * outcome. This is the same contract the deletion route holds, and for the same reason.
     *
     * THE AGENT ID TRAVELS IN THE BODY -- `{"agent_id": "7"}` -- because the dispatcher POSTs a
     * task row's PAYLOAD verbatim and sets no headers of its own. `X-Wazuh-Agent-Id` is ignored
     * even when present: honouring it would hide a producer that forgot to write the id into the
     * payload.
     *
     * THE ADMISSION ROUTE STAYS WHERE IT IS. `POST /vulnerability-detector/scan` on the scanner's
     * own socket keeps its validation, its readiness preflight and its `503 scan_queue_full`
     * vocabulary, because remoted distinguishes that code from the content manager's
     * `ondemand_queue_full` for metrics. What changes there is only what it does after admitting:
     * create a task row instead of pushing onto an in-memory deque.
     */

    /// @brief The verb. POST because the caller's C-side HTTP helper (uhttp_*) only speaks POST.
    constexpr wazuh::uds_http::Method method()
    {
        return wazuh::uds_http::Method::Post;
    }

    /// @brief The path. `_internal` marks it as a manager-internal contract between two daemons of
    /// the same version -- nothing outside the manager may target it, and it carries no
    /// compatibility promise.
    constexpr const char* path()
    {
        return "/_internal/vd/scan";
    }

    /**
     * @brief This route's own response backstop, overriding the server-wide 300 s.
     *
     * Same cross-daemon coupling the deletion route has, and the same rule: the transport's
     * backstop is written around the PEER's deadline being the shorter one, so it must sit above
     * whatever the Task Manager allows. `manager_task_vd_scan_timeout` is 300 s, which is exactly
     * the server-wide value -- a tie, so which of the two fires first is a coin flip, and half the
     * time a scan that succeeded is reported to the dispatcher as a synthesized 504.
     *
     * 450 s restores the intended ordering with 50% headroom, the same ratio the deletion route
     * uses over its own 600 s. It must stay above `manager_task_vd_scan_timeout`.
     *
     * This is a leak backstop, not a quality-of-service deadline: the real bound on a scan is the
     * dispatcher's own request timeout, and there is no ground truth for scan duration in the tree
     * to set either from. Calibrate from `vd.dispatch.scan.duration`, the microsecond histogram VD
     * already records around `triggerAgentScan`.
     */
    constexpr std::size_t responseTimeoutSeconds()
    {
        return 450;
    }

    /**
     * @brief Everything the handler needs, captured by value at registration.
     *
     * Weak, like every other route: the facade's stop() resets it and the weak capture keeps that
     * reset destructive.
     *
     * There is deliberately NO indexer connector here, unlike the deletion route. The lane worker
     * re-checks indexer health and feed readiness at dispatch and answers 503 either way, so an
     * admission gate would duplicate that check to reach the same answer -- and unlike a deletion,
     * a refused scan occupies nothing worth protecting: the lane's own queue bound is the capacity
     * control, and it is checked here.
     *
     * requestCounters covers only the responses THIS handler sends (the inline rejections); the
     * terminal response is counted by the lane, at the site that sends it, so a request is counted
     * exactly once.
     */
    struct Dependencies
    {
        std::weak_ptr<invsync::vd::VdScanLane> scanLane;
        invsync::metrics::RequestCounters requestCounters;
    };

    /**
     * @brief Build the route handler: validate the body (400), enqueue a VdScanRequest item WITH
     *        its responder, and answer nothing -- the lane answers once the scan has run.
     */
    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies);

} // namespace invsync::endpoints::vd_scan

#endif // _INVSYNC_ENDPOINTS_VD_SCAN_ENDPOINT_HPP
