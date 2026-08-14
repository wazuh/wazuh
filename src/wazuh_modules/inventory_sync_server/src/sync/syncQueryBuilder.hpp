/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_SYNC_QUERY_BUILDER_HPP
#define _INVSYNC_SYNC_QUERY_BUILDER_HPP

#include "timeHelper.h"

#include <json.hpp>

#include <cstdint>
#include <string>
#include <vector>

/*
 * Query builders for the metadata and group session modes, ported VERBATIM from the legacy
 * module's InventorySyncQueryBuilder (inventory_sync/src/inventorySyncQueryBuilder.hpp) -- only
 * the five builders this server consumes; the vulnerability-scanner-only ones stay behind and
 * move to VD's own tree when it migrates.
 *
 * The painless scripts are the CONTRACT with the documents already in the indexer, so they are kept
 * byte-identical on purpose:
 *  - the *UpdateQuery pair implements the external_gte guard (only update documents whose
 *    state.document_version is absent or <= the session's global_version) and stamps
 *    state.modified_at;
 *  - the *CheckQuery pair is disaster recovery: compare and fix ONLY on mismatch (ctx.op = 'noop'
 *    otherwise) and deliberately do NOT touch document_version or modified_at.
 */
namespace invsync::sync::querybuilder
{

    /// Append a cluster.name filter to a bool/must query (no-op if @p clusterName is empty).
    inline void addClusterScope(nlohmann::json& query, const std::string& clusterName)
    {
        if (!clusterName.empty())
        {
            query["query"]["bool"]["must"].push_back({{"term", {{"wazuh.cluster.name", clusterName}}}});
        }
    }

    inline nlohmann::json buildMetadataUpdateQuery(const std::string& agentId,
                                                   const std::string& agentName,
                                                   const std::string& agentVersion,
                                                   const std::string& architecture,
                                                   const std::string& hostname,
                                                   const std::string& osname,
                                                   const std::string& osplatform,
                                                   const std::string& ostype,
                                                   const std::string& osversion,
                                                   std::uint64_t globalVersion)
    {
        nlohmann::json updateQuery;

        // Match wazuh.agent.id AND only update if version <= globalVersion (external_gte behavior):
        // documents where state.document_version is null OR <= globalVersion.
        updateQuery["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"] = agentId;
        updateQuery["query"]["bool"]["should"][0]["bool"]["must_not"]["exists"]["field"] = "state.document_version";
        updateQuery["query"]["bool"]["should"][1]["range"]["state.document_version"]["lte"] = globalVersion;
        updateQuery["query"]["bool"]["minimum_should_match"] = 1;

        const auto timestamp = Utils::getCurrentISO8601();

        std::string script = "ctx._source.wazuh.agent.id = params.id; "
                             "ctx._source.wazuh.agent.name = params.name; "
                             "ctx._source.wazuh.agent.version = params.version; "
                             "if (ctx._source.wazuh.agent.host == null) { ctx._source.wazuh.agent.host = [:]; } "
                             "ctx._source.wazuh.agent.host.architecture = params.architecture; "
                             "ctx._source.wazuh.agent.host.hostname = params.hostname; "
                             "if (ctx._source.wazuh.agent.host.os == null) { ctx._source.wazuh.agent.host.os = [:]; } "
                             "ctx._source.wazuh.agent.host.os.name = params.osname; "
                             "ctx._source.wazuh.agent.host.os.platform = params.osplatform; "
                             "ctx._source.wazuh.agent.host.os.type = params.ostype; "
                             "ctx._source.wazuh.agent.host.os.version = params.osversion; "
                             "if (ctx._source.state == null) { ctx._source.state = [:]; } "
                             "ctx._source.state.document_version = params.globalVersion; "
                             "ctx._source.state.modified_at = params.timestamp;";

        updateQuery["script"]["source"] = script;
        updateQuery["script"]["lang"] = "painless";
        updateQuery["script"]["params"]["id"] = agentId;
        updateQuery["script"]["params"]["name"] = agentName;
        updateQuery["script"]["params"]["version"] = agentVersion;
        updateQuery["script"]["params"]["architecture"] = architecture;
        updateQuery["script"]["params"]["hostname"] = hostname;
        updateQuery["script"]["params"]["osname"] = osname;
        updateQuery["script"]["params"]["osplatform"] = osplatform;
        updateQuery["script"]["params"]["ostype"] = ostype;
        updateQuery["script"]["params"]["osversion"] = osversion;
        updateQuery["script"]["params"]["globalVersion"] = globalVersion;
        updateQuery["script"]["params"]["timestamp"] = timestamp;

        return updateQuery;
    }

    inline nlohmann::json buildGroupsUpdateQuery(const std::string& agentId,
                                                 const std::vector<std::string>& groups,
                                                 std::uint64_t globalVersion)
    {
        nlohmann::json updateQuery;

        updateQuery["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"] = agentId;
        updateQuery["query"]["bool"]["should"][0]["bool"]["must_not"]["exists"]["field"] = "state.document_version";
        updateQuery["query"]["bool"]["should"][1]["range"]["state.document_version"]["lte"] = globalVersion;
        updateQuery["query"]["bool"]["minimum_should_match"] = 1;

        const auto timestamp = Utils::getCurrentISO8601();

        std::string script = "ctx._source.wazuh.agent.groups = params.groups; "
                             "if (ctx._source.state == null) { ctx._source.state = [:]; } "
                             "ctx._source.state.document_version = params.globalVersion; "
                             "ctx._source.state.modified_at = params.timestamp;";

        updateQuery["script"]["source"] = script;
        updateQuery["script"]["lang"] = "painless";
        updateQuery["script"]["params"]["groups"] = groups;
        updateQuery["script"]["params"]["globalVersion"] = globalVersion;
        updateQuery["script"]["params"]["timestamp"] = timestamp;

        return updateQuery;
    }

    inline nlohmann::json buildMetadataCheckQuery(const std::string& agentId,
                                                  const std::string& agentName,
                                                  const std::string& agentVersion,
                                                  const std::string& architecture,
                                                  const std::string& hostname,
                                                  const std::string& osname,
                                                  const std::string& osplatform,
                                                  const std::string& ostype,
                                                  const std::string& osversion)
    {
        nlohmann::json updateQuery;

        updateQuery["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"] = agentId;

        // Compare and only update on mismatch. Does NOT touch document_version or modified_at:
        // this is disaster recovery, not a versioned write.
        std::string script =
            "boolean needsUpdate = false; "
            "if (ctx._source.wazuh.agent.id != params.id) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent.name != params.name) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent.version != params.version) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent?.host?.architecture != params.architecture) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent?.host?.hostname != params.hostname) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent?.host?.os?.name != params.osname) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent?.host?.os?.platform != params.osplatform) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent?.host?.os?.type != params.ostype) { needsUpdate = true; } "
            "if (ctx._source.wazuh.agent?.host?.os?.version != params.osversion) { needsUpdate = true; } "
            "if (!needsUpdate) { ctx.op = 'noop'; } else { "
            "  ctx._source.wazuh.agent.id = params.id; "
            "  ctx._source.wazuh.agent.name = params.name; "
            "  ctx._source.wazuh.agent.version = params.version; "
            "  if (ctx._source.wazuh.agent.host == null) { ctx._source.wazuh.agent.host = [:]; } "
            "  ctx._source.wazuh.agent.host.architecture = params.architecture; "
            "  ctx._source.wazuh.agent.host.hostname = params.hostname; "
            "  if (ctx._source.wazuh.agent.host.os == null) { ctx._source.wazuh.agent.host.os = [:]; } "
            "  ctx._source.wazuh.agent.host.os.name = params.osname; "
            "  ctx._source.wazuh.agent.host.os.platform = params.osplatform; "
            "  ctx._source.wazuh.agent.host.os.type = params.ostype; "
            "  ctx._source.wazuh.agent.host.os.version = params.osversion; "
            "}";

        updateQuery["script"]["source"] = script;
        updateQuery["script"]["lang"] = "painless";
        updateQuery["script"]["params"]["id"] = agentId;
        updateQuery["script"]["params"]["name"] = agentName;
        updateQuery["script"]["params"]["version"] = agentVersion;
        updateQuery["script"]["params"]["architecture"] = architecture;
        updateQuery["script"]["params"]["hostname"] = hostname;
        updateQuery["script"]["params"]["osname"] = osname;
        updateQuery["script"]["params"]["osplatform"] = osplatform;
        updateQuery["script"]["params"]["ostype"] = ostype;
        updateQuery["script"]["params"]["osversion"] = osversion;

        return updateQuery;
    }

    inline nlohmann::json buildGroupsCheckQuery(const std::string& agentId, const std::vector<std::string>& groups)
    {
        nlohmann::json updateQuery;

        updateQuery["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"] = agentId;

        std::string script = "boolean needsUpdate = false; "
                             "def currentGroups = ctx._source.wazuh.agent?.groups; "
                             "if (currentGroups == null && params.groups.size() > 0) { needsUpdate = true; } "
                             "else if (currentGroups != null) { "
                             "  if (currentGroups.size() != params.groups.size()) { needsUpdate = true; } "
                             "  else { "
                             "    def sortedCurrent = new ArrayList(currentGroups); "
                             "    Collections.sort(sortedCurrent); "
                             "    def sortedExpected = new ArrayList(params.groups); "
                             "    Collections.sort(sortedExpected); "
                             "    for (int i = 0; i < sortedCurrent.size(); i++) { "
                             "      if (sortedCurrent[i] != sortedExpected[i]) { needsUpdate = true; break; } "
                             "    } "
                             "  } "
                             "} "
                             "if (!needsUpdate) { ctx.op = 'noop'; } else { "
                             "  ctx._source.wazuh.agent.groups = params.groups; "
                             "}";

        updateQuery["script"]["source"] = script;
        updateQuery["script"]["lang"] = "painless";
        updateQuery["script"]["params"]["groups"] = groups;

        return updateQuery;
    }

} // namespace invsync::sync::querybuilder

#endif // _INVSYNC_SYNC_QUERY_BUILDER_HPP
