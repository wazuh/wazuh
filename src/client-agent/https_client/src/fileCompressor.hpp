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

#ifndef _HC_FILE_COMPRESSOR_HPP
#define _HC_FILE_COMPRESSOR_HPP

#include "spoolFile.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

/// Streams a file through zstd into a new spool file, one chunk at a time --
/// never loading more than one chunk of either the source or the compressed
/// output into memory, so a multi-MB /stateful session never sits fully in
/// RAM (matching the existing spool/sign design's own "flat memory"
/// property). Injected so tests can force compression failures without
/// touching zstd or the filesystem.
class IFileCompressor
{
    public:
        virtual ~IFileCompressor() = default;

        /// Compresses sourcePath (exactly sourceSize bytes) into a new,
        /// exclusively-created temp file under spoolDir. abortFlag, when
        /// non-null, is checked between chunks; a set flag aborts the
        /// compression (deleting the partial output) rather than running it
        /// to completion -- so a large session's compression can't stall
        /// agent shutdown. Returns the compressed SpoolFile and its size, or
        /// nullopt on any failure (unreadable source, disk full, zstd error,
        /// abort) -- callers fall back to sending the uncompressed original.
        virtual std::optional<std::pair<std::unique_ptr<SpoolFile>, uint64_t>>
                                                                            compress(const std::string& sourcePath, uint64_t sourceSize, const std::string& spoolDir,
                                                                                     const std::atomic<bool>* abortFlag) = 0;
};

/// Real implementation: ZSTD_compressStream2 at the same level RetrySender
/// uses for in-memory bodies, streamed in 64 KiB chunks (matching
/// cmacSigner.cpp::signFile() and the manager's zstdDecoder.cpp).
class ZstdFileCompressor final : public IFileCompressor
{
    public:
        std::optional<std::pair<std::unique_ptr<SpoolFile>, uint64_t>>
                                                                    compress(const std::string& sourcePath, uint64_t sourceSize, const std::string& spoolDir,
                                                                             const std::atomic<bool>* abortFlag) override;
};

#endif // _HC_FILE_COMPRESSOR_HPP
