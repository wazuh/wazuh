/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "fileCompressor.hpp"

#include "exclusiveTempFile.hpp"

#include <zstd.h>

#include <array>
#include <cstdio>

namespace
{
    constexpr size_t FILE_CHUNK = 64 * 1024; // Matches the manager's zstdDecoder.cpp.
    // Matches the level RetrySender uses for in-memory bodies (retrySender.cpp).
    constexpr int kCompressionLevel = 3;

    using FilePtr = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

    struct CCtxGuard
    {
        ZSTD_CCtx* ctx;
        ~CCtxGuard()
        {
            ZSTD_freeCCtx(ctx);
        }
    };
} // namespace

std::optional<std::pair<std::unique_ptr<SpoolFile>, uint64_t>> ZstdFileCompressor::compress(
                                                                const std::string& sourcePath, uint64_t sourceSize, const std::string& spoolDir, const std::atomic<bool>* abortFlag)
{
    const FilePtr source {std::fopen(sourcePath.c_str(), "rb"), std::fclose};

    if (!source)
    {
        return std::nullopt;
    }

    std::string destPath;
    const int destFd = createExclusiveTempFile(spoolDir, "hc_zstd_", destPath);

    if (destFd < 0)
    {
        return std::nullopt;
    }

    // Declared before `dest`, so destroyed after it: whichever way this returns, the FILE* is
    // closed BEFORE the temp file is removed. Windows refuses to delete a file that still has an
    // open handle (createExclusiveTempFile opens _SH_DENYRW, which never grants FILE_SHARE_DELETE),
    // so removing it while the FILE* was still open left the temp file in the spool directory
    // permanently -- notably once per agent shutdown that aborted a /stateful session
    // compression. POSIX unlinks an open file happily, which is why only Windows leaked.
    SpoolFile compressed {std::move(destPath)};

#ifdef WIN32
    FilePtr dest {_fdopen(destFd, "wb"), std::fclose};
#else
    FilePtr dest {fdopen(destFd, "wb"), std::fclose};
#endif

    if (!dest)
    {
        closeExclusiveTempFile(destFd); // fdopen() failed: the fd is still ours to close.
        return std::nullopt; // LCOV_EXCL_LINE: fdopen() on a just-opened fd doesn't fail in practice.
    }

    ZSTD_CCtx* cctx = ZSTD_createCCtx();

    if (cctx == nullptr)
    {
        return std::nullopt; // LCOV_EXCL_LINE: allocation failure only.
    }

    const CCtxGuard guard {cctx};

    if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, kCompressionLevel)) ||
            ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(cctx, sourceSize)))
    {
        return std::nullopt; // LCOV_EXCL_LINE: cannot fail on a freshly created CCtx.
    }

    std::array<uint8_t, FILE_CHUNK> inChunk {};
    std::array<uint8_t, FILE_CHUNK> outChunk {};
    uint64_t compressedSize = 0;

    auto flushOutput = [&](const ZSTD_outBuffer & output)
    {
        if (output.pos == 0)
        {
            return true;
        }

        if (std::fwrite(outChunk.data(), 1, output.pos, dest.get()) != output.pos)
        {
            return false; // LCOV_EXCL_LINE: write failure is not reproducible in tests.
        }

        compressedSize += output.pos;
        return true;
    };

    size_t bytesRead = 0;

    while ((bytesRead = std::fread(inChunk.data(), 1, inChunk.size(), source.get())) > 0)
    {
        if (abortFlag != nullptr && abortFlag->load())
        {
            return std::nullopt;
        }

        ZSTD_inBuffer input {inChunk.data(), bytesRead, 0};

        while (input.pos < input.size)
        {
            ZSTD_outBuffer output {outChunk.data(), outChunk.size(), 0};
            const size_t ret = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_continue);

            if (ZSTD_isError(ret) || !flushOutput(output))
            {
                return std::nullopt;
            }
        }
    }

    if (std::ferror(source.get()))
    {
        return std::nullopt;
    }

    // Flush the frame epilogue: feed no more input, ZSTD_e_end, until zstd
    // reports nothing left buffered (return value 0). Handles the empty-file
    // case correctly too (produces a minimal valid zstd frame).
    const ZSTD_inBuffer noMoreInput {nullptr, 0, 0};
    size_t remaining = 0;

    do
    {
        ZSTD_outBuffer output {outChunk.data(), outChunk.size(), 0};
        ZSTD_inBuffer endInput = noMoreInput;
        remaining = ZSTD_compressStream2(cctx, &output, &endInput, ZSTD_e_end);

        if (ZSTD_isError(remaining) || !flushOutput(output))
        {
            return std::nullopt;
        }
    }
    while (remaining != 0);

    // fclose() is where a buffered write finally reaches the disk, so a full filesystem can
    // surface as ENOSPC *here* and nowhere earlier: the fwrite() above only fails once a whole
    // stdio buffer has been flushed, so the last partial buffer's failure arrives at close time.
    // unique_ptr's deleter discards fclose()'s result, so relying on it would hand back a truncated
    // spool file as a complete compressed body, which /stateful would then upload in place of the
    // real session -- caught only by the manager rejecting the frame, if at all.
    if (std::fclose(dest.release()) != 0)
    {
        return std::nullopt; // LCOV_EXCL_LINE: needs a genuinely full filesystem, not reproducible in the unit tests.
    }

    return std::make_pair(std::make_unique<SpoolFile>(std::move(compressed)), compressedSize);
}
