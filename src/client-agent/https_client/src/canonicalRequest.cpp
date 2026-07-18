/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "canonicalRequest.hpp"

std::string canonicalRequestHead(const std::string& method, const std::string& target,
                                 const std::string& agentId, std::time_t timestamp)
{
    return "WAZUH-REQUEST\n1\n" + method + "\n" + target + "\n" + agentId + "\n" +
           std::to_string(timestamp) + "\n";
}

std::vector<uint8_t> buildCanonicalRequest(const std::string& method, const std::string& target,
                                           const std::string& agentId, std::time_t timestamp,
                                           const uint8_t* body, size_t bodyLength)
{
    const std::string head = canonicalRequestHead(method, target, agentId, timestamp);
    std::vector<uint8_t> buffer;
    buffer.reserve(head.size() + bodyLength);
    buffer.insert(buffer.end(), head.begin(), head.end());

    if (body != nullptr && bodyLength > 0)
    {
        buffer.insert(buffer.end(), body, body + bodyLength);
    }

    return buffer;
}
