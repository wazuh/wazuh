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
} // namespace InventorySyncQueryBuilder

#endif // _INVENTORY_SYNC_QUERY_BUILDER_HPP
