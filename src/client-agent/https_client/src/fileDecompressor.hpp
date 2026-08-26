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

#ifndef _HC_FILE_DECOMPRESSOR_HPP
#define _HC_FILE_DECOMPRESSOR_HPP

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>

/// Streams a zstd frame back out of a file into plain bytes, one chunk at a
/// time -- the mirror of IFileCompressor/ZstdFileCompressor (#38308), reading
/// instead of writing zstd. Unlike that class, the input here is untrusted
/// (a manager response, #38514): the declared window size is capped before
/// any decoder state is allocated, and the growing output is capped against
/// the caller's own byte budget, mirroring the manager's own request-body
/// decoder (remoted_module's zstdDecoder.cpp). Injected so tests can force
/// decompression failures without touching zstd or the filesystem.
class IFileDecompressor
{
    public:
        virtual ~IFileDecompressor() = default;

        /// Decompresses the zstd frame currently at `pathToReplace` and
        /// atomically replaces its content with the plain bytes -- same path
        /// throughout, so the caller's own file reference (a SpoolFile) never
        /// needs to change. `maxDecompressedBytes` bounds the growing output
        /// (0 = unlimited); the frame's declared window is capped
        /// independently, before any allocation, regardless of that budget.
        /// abortFlag, when non-null, is checked between chunks -- a set flag
        /// aborts the decompression (the original file is left untouched)
        /// rather than running it to completion, so a large download's
        /// decompression can't stall agent shutdown.
        ///
        /// On any failure (malformed frame, truncated frame, over-cap window,
        /// output exceeding maxDecompressedBytes, disk/zstd error, abort):
        /// returns nullopt, deletes only its own sibling temp file, and never
        /// touches `pathToReplace` -- the caller discards that file itself
        /// (the same RAII/SpoolFile path already used for a hash mismatch).
        ///
        /// On success: `pathToReplace` holds the decompressed bytes and the
        /// sibling temp file is gone; returns the decompressed byte count.
        virtual std::optional<uint64_t> decompress(const std::string& pathToReplace,
                                                    uint64_t maxDecompressedBytes,
                                                    const std::string& spoolDir,
                                                    const std::atomic<bool>* abortFlag) = 0;
};

/// Real implementation: ZSTD_decompressStream, streamed in 64 KiB chunks
/// (matches ZstdFileCompressor/cmacSigner.cpp::signFile()/the manager's
/// zstdDecoder.cpp), decompressing into a new exclusively-created sibling
/// file under spoolDir and renaming it over pathToReplace only once the
/// whole frame has validated successfully.
class ZstdFileDecompressor final : public IFileDecompressor
{
    public:
        std::optional<uint64_t> decompress(const std::string& pathToReplace,
                                            uint64_t maxDecompressedBytes,
                                            const std::string& spoolDir,
                                            const std::atomic<bool>* abortFlag) override;
};

#endif // _HC_FILE_DECOMPRESSOR_HPP
