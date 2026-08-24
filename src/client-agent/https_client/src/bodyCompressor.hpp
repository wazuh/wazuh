/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_BODY_COMPRESSOR_HPP
#define _HC_BODY_COMPRESSOR_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

/// zstd-compresses an in-memory body at the module's fixed level (matches the
/// manager's own test-only fixture compressor, zstdTestHelper.hpp). Extracted
/// out of RetrySender::attemptOnce() (#37835) so EnrollClient (#38465) can
/// share the exact same recipe instead of a second implementation.
/// @return nullopt on failure; the caller falls back to the original,
///         uncompressed body (a one-shot ZSTD_compress() into a
///         ZSTD_compressBound()-sized buffer should never actually fail, but
///         a request is never lost over it).
std::optional<std::vector<uint8_t>> compressBody(const uint8_t* body, size_t bodyLength);

#endif // _HC_BODY_COMPRESSOR_HPP
