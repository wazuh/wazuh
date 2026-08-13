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

#include "fileCompressor.hpp"

#include "exclusiveTempFile.hpp"

#include <zstd.h>

#include <array>
#include <cstdio>

namespace
{
    constexpr size_t FILE_CHUNK = 64 * 1024; // Matches cmacSigner.cpp/zstdDecoder.cpp.
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

std::optional<std::pair<std::unique_ptr<SpoolFile>, uint64_t>>
                                                            ZstdFileCompressor::compress(const std::string& sourcePath, uint64_t sourceSize,
                                                                                         const std::string& spoolDir, const std::atomic<bool>* abortFlag)
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

#ifdef WIN32
    FilePtr dest {_fdopen(destFd, "wb"), std::fclose};
#else
    FilePtr dest {fdopen(destFd, "wb"), std::fclose};
#endif

    if (!dest)
    {
        closeExclusiveTempFile(destFd); // fdopen() failed: the fd is still ours to close.
        std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: fdopen() on a just-opened fd doesn't fail in practice.
    }

    ZSTD_CCtx* cctx = ZSTD_createCCtx();

    if (cctx == nullptr)
    {
        std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: allocation failure only.
    }

    const CCtxGuard guard {cctx};

    if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, kCompressionLevel)) ||
            ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(cctx, sourceSize)))
    {
        std::remove(destPath.c_str());
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
            std::remove(destPath.c_str());
            return std::nullopt;
        }

        ZSTD_inBuffer input {inChunk.data(), bytesRead, 0};

        while (input.pos < input.size)
        {
            ZSTD_outBuffer output {outChunk.data(), outChunk.size(), 0};
            const size_t ret = ZSTD_compressStream2(cctx, &output, &input, ZSTD_e_continue);

            if (ZSTD_isError(ret) || !flushOutput(output))
            {
                std::remove(destPath.c_str());
                return std::nullopt;
            }
        }
    }

    if (std::ferror(source.get()))
    {
        std::remove(destPath.c_str());
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
            std::remove(destPath.c_str());
            return std::nullopt;
        }
    }
    while (remaining != 0);

    dest.reset(); // Close (flush to disk) before handing the path off.

    return std::make_pair(std::make_unique<SpoolFile>(destPath), compressedSize);
}
