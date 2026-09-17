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
/// (a manager response, #38514): every frame's declared window size is
/// capped before that frame's decoder state is allocated, and the growing
/// output is capped against the caller's own byte budget. Injected so tests
/// can force decompression failures without touching zstd or the filesystem.
class IFileDecompressor
{
    public:
        virtual ~IFileDecompressor() = default;

        /// Decompresses the zstd frame currently at `pathToReplace` and
        /// atomically replaces its content with the plain bytes -- same path
        /// throughout, so the caller's own file reference (a SpoolFile) never
        /// needs to change. The scratch file it decompresses into is created
        /// alongside `pathToReplace`, in that file's own directory, so the
        /// rename that swaps them can never cross a filesystem boundary --
        /// the caller does not get to choose (or mis-resolve) a spool dir.
        /// `maxDecompressedBytes` bounds the growing output (0 = unlimited);
        /// each frame's declared window is capped independently, before its
        /// allocation, regardless of that budget.
        /// abortFlag, when non-null, is checked between chunks -- a set flag
        /// aborts the decompression (the original file is left untouched)
        /// rather than running it to completion, so a large download's
        /// decompression can't stall agent shutdown.
        ///
        /// On any failure (malformed frame, truncated frame, over-cap window,
        /// output exceeding maxDecompressedBytes, a frame yielding no plain
        /// bytes at all, disk/zstd error, abort):
        /// returns nullopt, deletes only its own sibling temp file, and never
        /// touches `pathToReplace` -- the caller discards that file itself
        /// (the same RAII/SpoolFile path already used for a hash mismatch).
        ///
        /// On success: `pathToReplace` holds the decompressed bytes and the
        /// sibling temp file is gone; returns the decompressed byte count.
        virtual std::optional<uint64_t> decompress(const std::string& pathToReplace,
                                                   uint64_t maxDecompressedBytes,
                                                   const std::atomic<bool>* abortFlag) = 0;
};

/// Real implementation: ZSTD_decompressStream under a ZSTD_d_windowLogMax
/// ceiling, streamed in 64 KiB chunks (matches ZstdFileCompressor/
/// cmacSigner.cpp::signFile()), decompressing into a new exclusively-created
/// sibling file in pathToReplace's own directory and renaming it over
/// pathToReplace only once the whole frame has validated successfully.
class ZstdFileDecompressor final : public IFileDecompressor
{
    public:
        std::optional<uint64_t> decompress(const std::string& pathToReplace,
                                           uint64_t maxDecompressedBytes,
                                           const std::atomic<bool>* abortFlag) override;
};

#endif // _HC_FILE_DECOMPRESSOR_HPP
