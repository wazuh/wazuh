/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "keystore.hpp"

#include <charconv>
#include <fstream>
#include <sstream>

#include "cmac.hpp"

namespace remoted::auth
{

    namespace
    {
        bool isCommentOrBlank(const std::string& line)
        {
            return line.empty() || line[0] == '#' || line[0] == ' ';
        }

        // Matches OS_ReadKeys()'s "removed entry" check: the field right
        // after the id is '#' or '!' for a removed/disabled agent.
        bool isRemovedMarker(const std::string& field)
        {
            return !field.empty() && (field[0] == '#' || field[0] == '!');
        }

        std::vector<std::uint8_t> decodeKey(const std::string& hex)
        {
            if (hex.empty() || hex.size() % 2 != 0)
            {
                return {};
            }
            std::vector<std::uint8_t> bytes(hex.size() / 2);
            if (!fromLowerHex(hex, bytes.data(), bytes.size()))
            {
                return {};
            }
            return bytes;
        }

        // Non-negative integer, fully consuming the field. An agent id is always numeric by
        // design; a client.keys line whose id column isn't can never match a real lookup, so it
        // is skipped at load time rather than kept around as dead weight.
        std::optional<AgentId> parseAgentId(const std::string& id)
        {
            AgentId value = 0;
            const auto [ptr, ec] = std::from_chars(id.data(), id.data() + id.size(), value);
            if (id.empty() || ec != std::errc {} || ptr != id.data() + id.size())
            {
                return std::nullopt;
            }
            return value;
        }
    } // namespace

    Keystore::Keystore(std::string path)
        : m_path(std::move(path))
    {
        reload();
    }

    int Keystore::reload()
    {
        std::ifstream file(m_path);
        if (!file.is_open())
        {
            return -1;
        }

        std::unordered_map<AgentId, std::vector<std::uint8_t>> loaded;
        std::string line;
        int count = 0;

        while (std::getline(file, line))
        {
            if (isCommentOrBlank(line))
            {
                continue;
            }

            std::istringstream tokens(line);
            std::string id, name, ip, key;
            if (!(tokens >> id >> name >> ip >> key))
            {
                continue; // malformed line: fewer than 4 fields
            }

            if (isRemovedMarker(name))
            {
                continue; // removed/disabled entry -- same as OS_ReadKeys()
            }

            const auto agentId = parseAgentId(id);
            if (!agentId)
            {
                // TODO: Log warning: "client.keys line %d: agent id '%s' is not a non-negative integer, skipping"
                continue; // id column isn't numeric -- can never match a real lookup
            }

            loaded[*agentId] = decodeKey(key);
            ++count;
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_keys = std::move(loaded);
        }
        return count;
    }

    std::optional<std::vector<std::uint8_t>> Keystore::keyFor(AgentId agentId) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_keys.find(agentId);
        if (it == m_keys.end())
        {
            return std::nullopt;
        }
        return it->second;
    }

} // namespace remoted::auth
