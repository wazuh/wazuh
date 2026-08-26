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

/// The #38438 enrollment canonical request head: "WAZUH-ENROLL\n1\nMETHOD\ntarget\nts\n".
/// Used only for the password-mode WazuhEnroll signature (EnrollSigner); mTLS/open
/// enrollment sign nothing. Transitional: the agent<->manager request credential is
/// the `wazuh-agent+jwt` bearer (jwtSigner.hpp) and has no canonical request; this
/// file goes away when /enroll moves to its own JWT profile.
std::string enrollCanonicalRequestHead(const std::string& method, const std::string& target, std::time_t timestamp);

/// Head + body in one buffer, enrollment variant (memory-body convenience).
std::vector<uint8_t> buildEnrollCanonicalRequest(const std::string& method,
                                                 const std::string& target,
                                                 std::time_t timestamp,
                                                 const uint8_t* body,
                                                 size_t bodyLength);

#endif // _HC_CANONICAL_REQUEST_HPP
