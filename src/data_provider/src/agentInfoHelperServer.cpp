/*
 * Wazuh SysInfo - Server/Manager Implementation
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentInfoHelper.h"

namespace AgentInfoHelper
{
    std::string readAgentIdImpl(const char*)
    {
        // Server/Manager always uses "000" as agent ID
        return "000";
    }

    std::string readAgentNameImpl(const char*, std::function<std::string()> getHostname)
    {
        // Server/Manager uses hostname as agent name
        if (getHostname)
        {
            return getHostname();
        }

        return "";
    }
}
