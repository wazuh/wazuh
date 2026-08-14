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

/// SHA-256 of a byte range as lowercase hex: the settings_hash recipe.
/// Empty on an (unreproducible) EVP failure.
std::string sha256Hex(const void* data, size_t length);

/// SHA-256 of a file as lowercase hex: the config_hash recipe ("SHA256 hash
/// of group configuration"). nullopt when unreadable.
std::optional<std::string> sha256FileHex(const std::string& path);

/// SHA-1 of a byte range as lowercase hex. Test/verification helper
/// mirroring sha256Hex; see sha1FileHex for the recipe this backs.
std::string sha1Hex(const void* data, size_t length);

/// SHA-1 of a file as lowercase hex: the remote_upgrade WPK verification
/// recipe (task payload's wpk_sha1). A different digest than config's on
/// purpose -- it is the manager's own WPK checksum convention (matching the
/// legacy upgrade module's OS_SHA1_File), not something this module gets to
/// choose. nullopt when unreadable.
std::optional<std::string> sha1FileHex(const std::string& path);

#endif // _HC_DIGEST_HPP
