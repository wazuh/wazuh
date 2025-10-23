/*
 * Wazuh SysInfo - Agent Implementation
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentInfoHelper.h"
#include <fstream>

namespace AgentInfoHelper
{
    std::string readAgentIdImpl(const char* keysFilePath)
    {
        std::string agentId;
        std::ifstream file(keysFilePath);

        if (file.is_open())
        {
            std::string line;

            if (std::getline(file, line) && !line.empty())
            {
                // client.keys format: ID NAME IP KEY
                size_t firstSpace = line.find(' ');

                if (firstSpace != std::string::npos)
                {
                    agentId = line.substr(0, firstSpace);
                }
            }
        }

        return agentId;
    }

    std::string readAgentNameImpl(const char* keysFilePath, std::function<std::string()>)
    {
        std::string agentName;
        std::ifstream file(keysFilePath);

        if (file.is_open())
        {
            std::string line;

            if (std::getline(file, line) && !line.empty())
            {
                // client.keys format: ID NAME IP KEY
                size_t firstSpace = line.find(' ');

                if (firstSpace != std::string::npos)
                {
                    size_t secondSpace = line.find(' ', firstSpace + 1);

                    if (secondSpace != std::string::npos)
                    {
                        agentName = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
                    }
                }
            }
        }

        return agentName;
    }
}
