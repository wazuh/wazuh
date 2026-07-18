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

#ifndef _HC_CANONICAL_REQUEST_HPP
#define _HC_CANONICAL_REQUEST_HPP

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

/// The #37732 canonical-request head: "WAZUH-REQUEST\n1\nMETHOD\ntarget\nid\nts\n".
/// The MAC covers this head followed by the exact body bytes, no normalization.
std::string canonicalRequestHead(const std::string& method, const std::string& target,
                                 const std::string& agentId, std::time_t timestamp);

/// Head + body in one buffer (memory-body convenience).
std::vector<uint8_t> buildCanonicalRequest(const std::string& method, const std::string& target,
                                           const std::string& agentId, std::time_t timestamp,
                                           const uint8_t* body, size_t bodyLength);

#endif // _HC_CANONICAL_REQUEST_HPP
