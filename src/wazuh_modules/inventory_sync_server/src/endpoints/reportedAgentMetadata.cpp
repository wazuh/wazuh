/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "reportedAgentMetadata.hpp"

#include "common/agentMetadataLimits.hpp"

#include <string>
#include <utility>

namespace
{
    bool isBoundedString(const nlohmann::json& value, std::size_t maxBytes)
    {
        return value.is_string() && value.get_ref<const std::string&>().size() <= maxBytes;
    }

    /// The member @p key of @p parent when it is an object; null otherwise. A member that is there
    /// but is not an object counts as one bad field.
    const nlohmann::json* objectMember(const nlohmann::json* parent, const char* key, std::size_t& dropped)
    {
        if (parent == nullptr)
        {
            return nullptr;
        }

        const auto it = parent->find(key);

        if (it == parent->end())
        {
            return nullptr;
        }

        if (!it->is_object())
        {
            ++dropped;
            return nullptr;
        }

        return &*it;
    }

    std::string hostString(const nlohmann::json* parent, const char* key, std::size_t& dropped)
    {
        if (parent == nullptr)
        {
            return {};
        }

        const auto it = parent->find(key);

        if (it == parent->end())
        {
            return {};
        }

        if (!isBoundedString(*it, invsync::common::MAX_AGENT_HOST_FIELD_BYTES))
        {
            ++dropped;
            return {};
        }

        return it->get<std::string>();
    }

    nlohmann::json groups(const nlohmann::json& agent, std::size_t& dropped)
    {
        const auto it = agent.find("groups");

        if (it == agent.end())
        {
            return nlohmann::json::array();
        }

        if (!it->is_array() || it->size() > invsync::common::MAX_AGENT_GROUPS)
        {
            ++dropped;
            return nlohmann::json::array();
        }

        for (const auto& group : *it)
        {
            if (!isBoundedString(group, invsync::common::MAX_AGENT_GROUP_NAME_BYTES) ||
                group.get_ref<const std::string&>().empty())
            {
                ++dropped;
                return nlohmann::json::array();
            }
        }

        return *it;
    }
} // namespace

namespace invsync::endpoints
{

    std::size_t stampReportedAgentMetadata(const nlohmann::json& payload, nlohmann::json& document)
    {
        std::size_t dropped {0};

        const auto agentIt = payload.find("agent");

        if (agentIt == payload.end())
        {
            return dropped;
        }

        if (!agentIt->is_object())
        {
            return ++dropped;
        }

        const auto* host = objectMember(&*agentIt, "host", dropped);
        const auto* os = objectMember(host, "os", dropped);

        nlohmann::json hostDocument;
        hostDocument["architecture"] = hostString(host, "architecture", dropped);
        hostDocument["hostname"] = hostString(host, "hostname", dropped);
        hostDocument["os"]["name"] = hostString(os, "name", dropped);
        hostDocument["os"]["platform"] = hostString(os, "platform", dropped);
        hostDocument["os"]["type"] = hostString(os, "type", dropped);
        hostDocument["os"]["version"] = hostString(os, "version", dropped);

        document["/wazuh/agent/groups"_json_pointer] = groups(*agentIt, dropped);
        document["/wazuh/agent/host"_json_pointer] = std::move(hostDocument);

        return dropped;
    }

} // namespace invsync::endpoints
