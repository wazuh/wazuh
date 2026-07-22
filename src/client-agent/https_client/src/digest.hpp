/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_DIGEST_HPP
#define _HC_DIGEST_HPP

#include <cstddef>
#include <optional>
#include <string>

/// SHA-256 of a byte range as lowercase hex: the settings_hash recipe
/// (#37733 5.1.1). Empty on an (unreproducible) EVP failure.
std::string sha256Hex(const void* data, size_t length);

/// SHA-256 of a file as lowercase hex: the config_hash recipe ("SHA256 hash
/// of group configuration", #37733 OpenAPI). nullopt when unreadable.
std::optional<std::string> sha256FileHex(const std::string& path);

#endif // _HC_DIGEST_HPP
