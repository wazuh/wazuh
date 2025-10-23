/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AGENT_INFO_HELPER_H
#define _AGENT_INFO_HELPER_H

#include <string>
#include <vector>
#include <fstream>
#include <functional>
#include "defs.h"

namespace AgentInfoHelper
{
    /**
     * @brief Implementation function for reading agent ID
     * Implemented in agentInfoHelperAgent.cpp or agentInfoHelperServer.cpp
     * depending on CLIENT define
     */
    std::string readAgentIdImpl(const char* keysFilePath);

    /**
     * @brief Implementation function for reading agent name
     * Implemented in agentInfoHelperAgent.cpp or agentInfoHelperServer.cpp
     * depending on CLIENT define
     */
    std::string readAgentNameImpl(const char* keysFilePath, std::function<std::string()> getHostname);

    /**
     * @brief Read agent ID
     * For agents (CLIENT defined): reads from client.keys file
     * For server/manager: returns "000"
     * @param keysFilePath Path to the client.keys file
     * @return Agent ID string
     */
    inline std::string readAgentId(const char* keysFilePath = KEYS_FILE)
    {
        return readAgentIdImpl(keysFilePath);
    }

    /**
     * @brief Read agent name
     * For agents (CLIENT defined): reads from client.keys file
     * For server/manager: returns hostname from system
     * @param keysFilePath Path to the client.keys file (used only for agents)
     * @param getHostname Callback to get hostname (used only for server/manager)
     * @return Agent name string
     */
    inline std::string readAgentName(const char* keysFilePath = KEYS_FILE,
                                     std::function<std::string()> getHostname = nullptr)
    {
        return readAgentNameImpl(keysFilePath, getHostname);
    }

    /**
     * @brief Read agent groups from merged.mg file
     * @param mergedFilePath Path to the merged.mg file
     * @return Vector of group names
     */
    inline std::vector<std::string> readAgentGroups(const char* mergedFilePath)
    {
        std::vector<std::string> groups;
        std::ifstream file(mergedFilePath);

        if (file.is_open())
        {
            std::string line;

            while (std::getline(file, line))
            {
                // Look for XML comment with "Source file:"
                size_t commentStart = line.find("<!--");
                size_t sourceFilePos = line.find("Source file:");

                if (commentStart != std::string::npos && sourceFilePos != std::string::npos)
                {
                    // Extract the path after "Source file:"
                    size_t pathStart = sourceFilePos + 12; // Length of "Source file:"

                    // Skip any leading whitespace after "Source file:"
                    while (pathStart < line.length() && std::isspace(line[pathStart]))
                    {
                        pathStart++;
                    }

                    // Check for both Unix and Windows path separators
                    size_t pathEnd = line.find("/agent.conf", pathStart);

                    if (pathEnd == std::string::npos)
                    {
                        pathEnd = line.find("\\agent.conf", pathStart);
                    }

                    if (pathEnd != std::string::npos && pathEnd > pathStart)
                    {
                        std::string groupName = line.substr(pathStart, pathEnd - pathStart);

                        // Trim whitespace from group name
                        size_t start = groupName.find_first_not_of(" \t\r\n");
                        size_t end = groupName.find_last_not_of(" \t\r\n");

                        if (start != std::string::npos && end != std::string::npos)
                        {
                            groupName = groupName.substr(start, end - start + 1);

                            if (!groupName.empty())
                            {
                                groups.push_back(groupName);
                            }
                        }
                    }
                }
            }
        }

        return groups;
    }
}

#endif // _AGENT_INFO_HELPER_H
