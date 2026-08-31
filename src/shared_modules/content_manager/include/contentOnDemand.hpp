/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_ON_DEMAND_HPP
#define _CONTENT_ON_DEMAND_HPP

#include <uds_http_server/IUdsHttpServer.hpp>

#include <memory>
#include <string>

namespace content_manager
{
    /**
     * @brief Queue one on-demand content update; the responder is answered when it resolves.
     *
     * The public seam the HTTP route (registered by the vulnerability scanner on its vd-http.sock
     * server) dispatches into: topic lookup, the short bounded lane and the update execution all
     * live behind it in OnDemandManager. Responses, all JSON:
     *   - 200 {"status":"ok"}                              update ran to completion
     *   - 404 {"error":"unknown_topic",...}                no such registered topic
     *   - 409 {"error":"update_in_progress",...}           an update for that topic already runs
     *   - 500 {"error":"update_failed",...}                the update itself threw
     *   - 503 {"error":"ondemand_queue_full"|"shutting_down",...}  lane full / tearing down
     *
     * Never blocks: safe to call from the transport's I/O threads (validation stays in the route
     * handler; this only enqueues or answers a rejection inline).
     *
     * @param topic  Registered content topic (the old GET /ondemand/<topic> path segment).
     * @param offset -1 (keep the current offset) or 0 (restart from scratch) -- pre-validated by
     *               the caller.
     * @param responder The transport's deferred responder for this request.
     */
    void
    dispatchOnDemand(const std::string& topic, int offset, std::shared_ptr<wazuh::uds_http::IHttpResponder> responder);
} // namespace content_manager

#endif // _CONTENT_ON_DEMAND_HPP
