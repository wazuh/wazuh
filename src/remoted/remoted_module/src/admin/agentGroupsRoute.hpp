/*
 * Wazuh remoted module - Admin route POST /_internal/agents/groups
 * Copyright (C) 2015, Wazuh Inc.
 * September 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ADMIN_AGENT_GROUPS_ROUTE_HPP
#define _REMOTED_ADMIN_AGENT_GROUPS_ROUTE_HPP

#include "control/agentRegistry.hpp"
#include "control/metrics.hpp"

#include <uds_http_server/IUdsHttpServer.hpp>

#include <cstddef>
#include <memory>

namespace remoted::admin
{
    /// Where clusterd names the agents whose memberships it just applied to this node's wazuh-db.
    constexpr auto AGENT_GROUPS_ROUTE_PATH {"/_internal/agents/groups"};

    /// Per-route body cap. One publication carries the ids of one agent-groups chunk (at most 64 KiB
    /// of wazuh-db output, of which the ids are a fraction), so this leaves ample headroom over the
    /// Control class's own 64 KiB; a body over it is a 413 from the transport.
    constexpr std::size_t kAgentGroupsMaxBodyBytes {256U * 1024U};

    /**
     * @brief The handler of POST /_internal/agents/groups: one membership publication from the
     * local cluster daemon, applied to the AgentRegistry /control and /download share.
     *
     * Body: `{"invalidate":[1,5]}` -- the agents whose memberships the cluster daemon just wrote to
     * wazuh-db, in order. Every other key is ignored, `set` included: a publication never carries
     * groups, because it describes the database as it was when the daemon wrote it, and a read this
     * node made since may already be newer. Only a wazuh-db read establishes a membership, so a
     * publication only withdraws one: an agent this node tracks has its membership made not
     * established (the next reader asks wazuh-db; a read in flight across it is superseded); an agent
     * it holds no entry for is skipped, never created. A late publication thus costs one extra read
     * and never overwrites or renews a newer one.
     *
     * Answers `200 {"invalidated":k,"skipped":m}` (per agent); `400` when `invalidate` is missing or
     * anything in it is malformed -- validated whole first, so nothing is applied; `503` once the
     * registry is gone (shutdown). Runs inline on an admin I/O thread: validation plus O(batch)
     * registry updates, no I/O. Trust is the socket's permissions (0660): whoever can reach it can
     * already rewrite memberships through wazuh-db's own socket.
     *
     * @param registry Weak: the route never extends the registry's lifetime.
     */
    wazuh::uds_http::RouteHandler makeAgentGroupsHandler(std::weak_ptr<control::AgentRegistry> registry,
                                                         control::PushMetrics metrics);
} // namespace remoted::admin

#endif // _REMOTED_ADMIN_AGENT_GROUPS_ROUTE_HPP
