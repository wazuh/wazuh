/*
 * Wazuh inventory sync - Query builders for indexer operations
 * Copyright (C) 2015, Wazuh Inc.
 * November 4, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_QUERY_BUILDER_HPP
#define _INVENTORY_SYNC_QUERY_BUILDER_HPP

#include "timeHelper.h"
#include <json.hpp>
#include <string>
#include <vector>

namespace InventorySyncQueryBuilder
{
    /// @brief Build update query for agent metadata across all documents
    /// @param agentId Agent ID to match
    /// @param agentName New agent name
    /// @param agentVersion New agent version
    /// @param architecture New architecture
    /// @param hostname New hostname
    /// @param osname New OS name
    /// @param osplatform New OS platform
    /// @param ostype New OS type
    /// @param osversion New OS version
    /// @param globalVersion Global version for external_gte behavior
    /// @return JSON update_by_query request body with bool query and Painless script
    inline nlohmann::json buildMetadataUpdateQuery(const std::string& agentId,
                                                   const std::string& agentName,
                                                   const std::string& agentVersion,
                                                   const std::string& architecture,
                                                   const std::string& hostname,
                                                   const std::string& osname,
                                                   const std::string& osplatform,
                                                   const std::string& ostype,
                                                   const std::string& osversion,
                                                   uint64_t globalVersion)
    {
        nlohmann::json updateQuery;

        // Build the query: match agent.id AND only update if version <= globalVersion (external_gte behavior)
        updateQuery["query"]["bool"]["must"][0]["term"]["agent.id"] = agentId;
        // Only update documents where version is null OR version <= globalVersion
        updateQuery["query"]["bool"]["should"][0]["bool"]["must_not"]["exists"]["field"] = "state.document_version";
        updateQuery["query"]["bool"]["should"][1]["range"]["state.document_version"]["lte"] = globalVersion;
        updateQuery["query"]["bool"]["minimum_should_match"] = 1;

        // Get current timestamp in ISO 8601 format
        const auto timestamp = Utils::getCurrentISO8601();

        // Build the Painless script to update agent metadata
        std::string script = "ctx._source.agent.id = params.id; "
                             "ctx._source.agent.name = params.name; "
                             "ctx._source.agent.version = params.version; "
                             "if (ctx._source.agent.host == null) { ctx._source.agent.host = [:]; } "
                             "ctx._source.agent.host.architecture = params.architecture; "
                             "ctx._source.agent.host.hostname = params.hostname; "
                             "if (ctx._source.agent.host.os == null) { ctx._source.agent.host.os = [:]; } "
                             "ctx._source.agent.host.os.name = params.osname; "
                             "ctx._source.agent.host.os.platform = params.osplatform; "
                             "ctx._source.agent.host.os.type = params.ostype; "
                             "ctx._source.agent.host.os.version = params.osversion; "
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

    /// @brief Build update query for agent groups across all documents
    /// @param agentId Agent ID to match
    /// @param groups New groups array
    /// @param globalVersion Global version for external_gte behavior
    /// @return JSON update_by_query request body with bool query and Painless script
    inline nlohmann::json
    buildGroupsUpdateQuery(const std::string& agentId, const std::vector<std::string>& groups, uint64_t globalVersion)
    {
        nlohmann::json updateQuery;

        // Build the query: match agent.id AND only update if version <= globalVersion (external_gte behavior)
        updateQuery["query"]["bool"]["must"][0]["term"]["agent.id"] = agentId;
        // Only update documents where version is null OR version <= globalVersion
        updateQuery["query"]["bool"]["should"][0]["bool"]["must_not"]["exists"]["field"] = "state.document_version";
        updateQuery["query"]["bool"]["should"][1]["range"]["state.document_version"]["lte"] = globalVersion;
        updateQuery["query"]["bool"]["minimum_should_match"] = 1;

        // Get current timestamp in ISO 8601 format
        const auto timestamp = Utils::getCurrentISO8601();

        // Build the Painless script to update agent groups
        std::string script = "ctx._source.agent.groups = params.groups; "
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

    /// @brief Build disaster recovery query for metadata check
    /// @details Compares each metadata field and only updates documents where fields differ (noop otherwise)
    /// @details Does NOT update document version or timestamp - this is disaster recovery, not a normal update
    /// @param agentId Agent ID to match
    /// @param agentName Expected agent name
    /// @param agentVersion Expected agent version
    /// @param architecture Expected architecture
    /// @param hostname Expected hostname
    /// @param osname Expected OS name
    /// @param osplatform Expected OS platform
    /// @param ostype Expected OS type
    /// @param osversion Expected OS version
    /// @return JSON update_by_query request body with conditional update script
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

        // Build the query: match agent.id only
        updateQuery["query"]["bool"]["must"][0]["term"]["agent.id"] = agentId;

        // Build the Painless script that compares fields and only updates if different
        // Note: Does NOT update document_version or timestamp - this is disaster recovery
        std::string script =
            "boolean needsUpdate = false; "
            "if (ctx._source.agent.id != params.id) { needsUpdate = true; } "
            "if (ctx._source.agent.name != params.name) { needsUpdate = true; } "
            "if (ctx._source.agent.version != params.version) { needsUpdate = true; } "
            "if (ctx._source.agent?.host?.architecture != params.architecture) { needsUpdate = true; } "
            "if (ctx._source.agent?.host?.hostname != params.hostname) { needsUpdate = true; } "
            "if (ctx._source.agent?.host?.os?.name != params.osname) { needsUpdate = true; } "
            "if (ctx._source.agent?.host?.os?.platform != params.osplatform) { needsUpdate = true; } "
            "if (ctx._source.agent?.host?.os?.type != params.ostype) { needsUpdate = true; } "
            "if (ctx._source.agent?.host?.os?.version != params.osversion) { needsUpdate = true; } "
            "if (!needsUpdate) { ctx.op = 'noop'; } else { "
            "  ctx._source.agent.id = params.id; "
            "  ctx._source.agent.name = params.name; "
            "  ctx._source.agent.version = params.version; "
            "  if (ctx._source.agent.host == null) { ctx._source.agent.host = [:]; } "
            "  ctx._source.agent.host.architecture = params.architecture; "
            "  ctx._source.agent.host.hostname = params.hostname; "
            "  if (ctx._source.agent.host.os == null) { ctx._source.agent.host.os = [:]; } "
            "  ctx._source.agent.host.os.name = params.osname; "
            "  ctx._source.agent.host.os.platform = params.osplatform; "
            "  ctx._source.agent.host.os.type = params.ostype; "
            "  ctx._source.agent.host.os.version = params.osversion; "
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

    /// @brief Build disaster recovery query for groups check
    /// @details Compares groups array and only updates documents where groups differ (noop otherwise)
    /// @details Does NOT update document version or timestamp - this is disaster recovery, not a normal update
    /// @param agentId Agent ID to match
    /// @param groups Expected groups array
    /// @return JSON update_by_query request body with conditional update script
    inline nlohmann::json buildGroupsCheckQuery(const std::string& agentId, const std::vector<std::string>& groups)
    {
        nlohmann::json updateQuery;

        // Build the query: match agent.id only
        updateQuery["query"]["bool"]["must"][0]["term"]["agent.id"] = agentId;

        // Build the Painless script that compares groups and only updates if different
        // Note: Does NOT update document_version or timestamp - this is disaster recovery
        std::string script = "boolean needsUpdate = false; "
                             "def currentGroups = ctx._source.agent?.groups; "
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
                             "  ctx._source.agent.groups = params.groups; "
                             "}";

        updateQuery["script"]["source"] = script;
        updateQuery["script"]["lang"] = "painless";
        updateQuery["script"]["params"]["groups"] = groups;

        return updateQuery;
    }
} // namespace InventorySyncQueryBuilder

#endif // _INVENTORY_SYNC_QUERY_BUILDER_HPP
