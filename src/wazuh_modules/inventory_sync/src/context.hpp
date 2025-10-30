/*
 * Wazuh inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * January 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_CONTEXT_HPP
#define _INVENTORY_SYNC_CONTEXT_HPP

#include "flatbuffers/include/inventorySync_generated.h"
#include <cstdint>
#include <string>
#include <vector>

struct Context final
{
    Wazuh::SyncSchema::Mode mode;
    Wazuh::SyncSchema::Option option;
    uint64_t sessionId;
    std::string moduleName;
    std::vector<std::string> indices;
    std::string agentId;
    std::string agentName;
    std::string agentVersion;
    std::string architecture;
    std::string hostname;
    std::string osname;
    std::string osplatform;
    std::string ostype;
    std::string osversion;
    std::vector<std::string> groups;
    uint64_t globalVersion;
    bool transactionDispatched = false;
};

#endif // _INVENTORY_SYNC_CONTEXT_HPP
