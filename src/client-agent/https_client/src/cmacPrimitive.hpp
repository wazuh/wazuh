/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 26, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CMAC_PRIMITIVE_HPP
#define _HC_CMAC_PRIMITIVE_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

/// AES-CMAC(key, message) as 32 lowercase hex chars, via OpenSSL 3 EVP_MAC
/// (the vendored crypto). The cipher follows the key length (16/24/32 ->
/// AES-128/192/256); any other length is refused.
///
/// Transitional: the agent<->manager request credential is the `wazuh-agent+jwt`
/// bearer (jwtSigner.hpp) and no longer uses CMAC. This primitive survives only
/// for the password-mode WazuhEnroll signature (enrollSigner.hpp) until /enroll
/// moves to its own JWT profile, when it goes away with it.
std::optional<std::string> cmacHex(const std::vector<uint8_t>& key, const uint8_t* message, size_t messageLength);

#endif // _HC_CMAC_PRIMITIVE_HPP
