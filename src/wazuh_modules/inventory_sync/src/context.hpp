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

struct Context final
{
    Wazuh::SyncSchema::Mode mode;
    uint64_t sessionId;
    std::string agentId;
    std::string agentName;
    std::string agentIp;
    std::string agentVersion;
    std::string moduleName;
    bool transactionDispatched = false;
};

#endif // _INVENTORY_SYNC_CONTEXT_HPP
