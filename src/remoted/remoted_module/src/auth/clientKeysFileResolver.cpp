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

#include "clientKeysFileResolver.hpp"

#include <fstream>
#include <sstream>

#include "cmac.hpp"

namespace wazuh_auth
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
    } // namespace

    ClientKeysFileResolver::ClientKeysFileResolver(std::string path)
        : m_path(std::move(path))
    {
        reload();
    }

    int ClientKeysFileResolver::reload()
    {
        std::ifstream file(m_path);
        if (!file.is_open())
        {
            return -1;
        }

        std::unordered_map<std::string, std::vector<std::uint8_t>> loaded;
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

            loaded[id] = decodeKey(key);
            ++count;
        }

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_keys = std::move(loaded);
        }
        return count;
    }

    std::optional<std::vector<std::uint8_t>> ClientKeysFileResolver::resolve(const std::string& agentId) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto it = m_keys.find(agentId);
        if (it == m_keys.end())
        {
            return std::nullopt;
        }
        return it->second;
    }

} // namespace wazuh_auth
