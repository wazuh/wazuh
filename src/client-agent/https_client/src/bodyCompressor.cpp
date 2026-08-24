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

#include "bodyCompressor.hpp"

#include <zstd.h>

namespace
{
    // Matches the level the manager's own test-only compressor
    // (zstdTestHelper.hpp's zstdCompress()) uses to build its zstd fixtures.
    constexpr int kCompressionLevel = 3;
} // namespace

std::optional<std::vector<uint8_t>> compressBody(const uint8_t* body, size_t bodyLength)
{
    std::vector<uint8_t> compressed(ZSTD_compressBound(bodyLength));
    const size_t written =
        ZSTD_compress(compressed.data(), compressed.size(), body, bodyLength, kCompressionLevel);

    if (ZSTD_isError(written))
    {
        return std::nullopt; // LCOV_EXCL_LINE: cannot fail for a ZSTD_compressBound()-sized buffer.
    }

    compressed.resize(written);
    return compressed;
}
