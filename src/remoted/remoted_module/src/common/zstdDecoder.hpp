/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_ZSTD_DECODER_HPP
#define _REMOTED_COMMON_ZSTD_DECODER_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <variant>

namespace remoted::common
{

    /**
     * @brief Why zstdDecode() failed.
     */
    enum class ZstdDecodeError
    {
        Malformed, ///< Not a valid/complete zstd frame (bad magic, truncated, oversized window, etc.).
        TooLarge,  ///< Decompressing would exceed the caller's maxOutputSize.
    };

    /**
     * @brief Decompress a zstd-encoded buffer, bounded to @p maxOutputSize.
     *
     * Streams through zstd's ZSTD_decompressStream() in fixed-size chunks and checks the running
     * output size after every chunk, so a highly compressed "decompression bomb" is rejected the
     * moment it crosses @p maxOutputSize -- the full decompressed payload is never materialized in
     * memory.
     *
     * @param compressed    Zstd-encoded input bytes (the exact wire body).
     * @param maxOutputSize Hard cap on the decompressed size, in bytes.
     * @return The decompressed bytes on success, or the failure reason.
     */
    std::variant<std::string, ZstdDecodeError> zstdDecode(std::string_view compressed, std::size_t maxOutputSize);

} // namespace remoted::common

#endif // _REMOTED_COMMON_ZSTD_DECODER_HPP
