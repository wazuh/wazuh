/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_ENDPOINTS_REPORTED_AGENT_METADATA_HPP
#define _INVSYNC_ENDPOINTS_REPORTED_AGENT_METADATA_HPP

#include <cstddef>
#include <json.hpp>

namespace invsync::endpoints
{

    /**
     * @brief Copy the agent's groups and host from a /stats or /config report into the document
     *        this module indexes, as `wazuh.agent.groups` and `wazuh.agent.host`.
     *
     * The agent reports them under a root `agent` object, the same block its /stateless header
     * carries:
     *
     * ```json
     * {"agent": {"groups": ["default"],
     *            "host": {"architecture": …, "hostname": …,
     *                     "os": {"name": …, "platform": …, "type": …, "version": …}}}}
     * ```
     *
     * Only those fields are copied, one by one, so a report cannot write any other `wazuh.agent.*`
     * path: not the id, which stays the authenticated one, and nothing the index template does not
     * map, which it would reject along with the whole document.
     *
     * When `agent` is an object, the full shape is written, like the `wazuh-states-*` documents: a
     * missing host string becomes `""` and missing groups `[]`. A field that fails validation is
     * written the same way and counted. `groups` is all or nothing: one bad entry empties the list
     * rather than storing a partial membership.
     *
     * Bad metadata never rejects the report. It is descriptive, the agent resends the same values
     * every cycle, and a 400 would stop that agent's reports for as long as they stay bad.
     *
     * When `agent` is missing (an agent that predates these fields) nothing is written; when it is
     * not an object, nothing is written and it counts as one bad field.
     *
     * @param payload  The agent's parsed report.
     * @param document The document being built; only `/wazuh/agent/groups` and `/wazuh/agent/host`
     *                 are written.
     * @return How many fields failed validation.
     */
    std::size_t stampReportedAgentMetadata(const nlohmann::json& payload, nlohmann::json& document);

} // namespace invsync::endpoints

#endif // _INVSYNC_ENDPOINTS_REPORTED_AGENT_METADATA_HPP
