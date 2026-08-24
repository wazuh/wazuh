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

/// The #38438 enrollment canonical request head: "WAZUH-ENROLL\n1\nMETHOD\ntarget\nts\n".
/// Omits the agent-id line the normal request head carries (canonicalRequestHead
/// above): an enrolling agent has no id yet. Used only for the password-mode
/// WazuhEnroll signature (EnrollSigner); mTLS/open enrollment sign nothing.
std::string enrollCanonicalRequestHead(const std::string& method, const std::string& target,
                                       std::time_t timestamp);

/// Head + body in one buffer, enrollment variant (memory-body convenience).
std::vector<uint8_t> buildEnrollCanonicalRequest(const std::string& method, const std::string& target,
                                                 std::time_t timestamp, const uint8_t* body,
                                                 size_t bodyLength);

/// #38492/#38491: joins the configured reverse-proxy path segment (already
/// normalized -- no leading/trailing '/', e.g. "wazuh-manager") with a bare
/// endpoint target (e.g. "/stateless") into "/wazuh-manager/stateless".
/// Returns target unchanged when endpoint is empty.
///
/// The manager's own auth middleware CMACs the literal wire request-target
/// (RestinioHttpServer.cpp: `request.target = req->header().request_target()`,
/// fed straight into authMiddleware.cpp's signature check) -- so unlike the
/// #37732/#38494 invariant for compression (never sign transport-only bytes),
/// the endpoint prefix here is NOT transport-only: the manager the agent
/// talks to requires it inside the signed target, so this must be called
/// before signing, and its result must be the same string later appended to
/// ModuleConfig::baseUrl() for the actual wire URL.
std::string prefixedTarget(const std::string& endpoint, const std::string& target);

#endif // _HC_CANONICAL_REQUEST_HPP
