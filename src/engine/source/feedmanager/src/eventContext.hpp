/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EVENT_CONTEXT_HPP
#define _EVENT_CONTEXT_HPP

#include "base/utils/rocksDBWrapper.hpp"
#include "flatbuffers/detached_buffer.h"
#include <nlohmann/json.hpp>
#include <vector>

enum class ResourceType
{
    UNKNOWN,
    CVE,
    TRANSLATION,
    VENDOR_MAP,
    OSCPE_RULES,
    CNA_MAPPING
};

/**
 * @brief EventContext class.
 *
 */
struct EventContext final
{
    const std::vector<char>& message;              ///< Message.
    const nlohmann::json& resource;                ///< Modified/created resource.
    flatbuffers::DetachedBuffer cve5Buffer;        ///< CVE data.
    utils::rocksdb::IRocksDBWrapper* feedDatabase; ///< CVEs database.
    ResourceType resourceType;                     ///< Resource type.
};

#endif // _EVENT_CONTEXT_HPP
