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
    /// Where clusterd publishes the memberships it applied to this node's wazuh-db.
    constexpr auto AGENT_GROUPS_ROUTE_PATH {"/_internal/agents/groups"};

    /// Per-route body cap. One publication carries one applied agent-groups chunk (at most 64 KiB
    /// of wazuh-db output, and the publication drops the agent names), so this leaves headroom
    /// over the Control class's own 64 KiB; a body over it is a 413 from the transport.
    constexpr std::size_t kAgentGroupsMaxBodyBytes {256U * 1024U};

    /**
     * @brief The handler of POST /_internal/agents/groups: one membership publication from the
     * local cluster daemon, applied to the AgentRegistry /control and /download share.
     *
     * Body: `{"set":[{"id":1,"groups":["default","g1"]}],"invalidate":[5]}` -- either key may be
     * absent, not both. Every `set` is applied before any `invalidate`, each in order (a repeated id:
     * the last write wins). A `set` establishes the groups of an agent this node already tracks (an
     * empty list is `default`); an `invalidate` makes its membership not established, so the next
     * reader asks wazuh-db; an agent this node holds no entry for is skipped, never created. Every
     * write is stamped under the registry's ordering rule, so a lookup that read wazuh-db before the
     * publication never overwrites it.
     *
     * Answers `200 {"updated":n,"invalidated":k,"skipped":m}` (per agent); `400` when anything in the
     * body is malformed -- validated whole first, so nothing is applied; `503` once the registry is
     * gone (shutdown). Runs inline on an admin I/O thread: validation plus O(batch) registry updates,
     * no I/O. Trust is the socket's permissions (0660): whoever can reach it can already rewrite
     * memberships through wazuh-db's own socket.
     *
     * @param registry Weak: the route never extends the registry's lifetime.
     */
    wazuh::uds_http::RouteHandler makeAgentGroupsHandler(std::weak_ptr<control::AgentRegistry> registry,
                                                         control::PushMetrics metrics);
} // namespace remoted::admin

#endif // _REMOTED_ADMIN_AGENT_GROUPS_ROUTE_HPP
