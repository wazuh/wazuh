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

#include "fileDecompressor.hpp"

#include "exclusiveTempFile.hpp"

#include <zstd.h>

#ifdef WIN32
#include <windows.h>
#endif

#include <array>
#include <cstdio>
#include <memory>

namespace
{
    constexpr size_t FILE_CHUNK = 64 * 1024; // Matches ZstdFileCompressor/cmacSigner.cpp/zstdDecoder.cpp.

    // Hard ceiling on the window size a frame may DECLARE, independent of maxDecompressedBytes.
    // The window size is attacker-chosen in a ~50-byte frame header and drives the decoder's
    // up-front allocation, so without this a tiny crafted response could make the agent reserve
    // zstd's own default limit (windowLog 27 = 128 MiB) regardless of how large a real merged.mg
    // is. 8 MiB is not tighter than what this feature's own legitimate traffic ever needs: zstd
    // level 3 (the fixed level used throughout this feature, see bodyCompressor.cpp/
    // fileCompressor.cpp) never requests a window above 8 MiB regardless of input size, so a
    // manager-produced frame for even a 64 MiB merged.mg still declares a window at or under this
    // bound.
    //
    // Handed to ZSTD_d_windowLogMax rather than checked against a parsed frame header: the decoder
    // then enforces it on EVERY frame it meets, before each allocation. A header parsed here could
    // only ever describe the FIRST frame, and ZSTD_decompressStream() goes on to decode
    // concatenated frames, re-allocating for each one -- so a ~100-byte response whose first frame
    // declares a small window and whose second declares windowLog 27 would sail past a header
    // check and still reserve 128 MiB.
    //
    // The value is a base-2 EXPONENT, not a byte count -- 2^23 = 8388608 bytes = 8 MiB -- because
    // that is the only form the wire format offers: a frame header stores the window as a 5-bit
    // exponent plus a 3-bit mantissa, never as a size. zstd converts it straight back to bytes
    // (zstd_decompress.c: `dctx->maxWindowSize = ((size_t)1) << value`) and compares the frame's
    // own decoded windowSize against that, so this stays byte-for-byte the `windowSize > 8 MiB`
    // rejection it replaces, inclusive edge and all. The mantissa is why windowSize is not always
    // a power of two, and why "exponent 23" is not by itself a pass: a header declaring exponent
    // 23 with a non-zero mantissa asks for 9-15 MiB and is refused, exactly as before. zstd's own
    // compressor always emits mantissa 0, so only a hand-crafted frame ever reaches that case.
    constexpr int kMaxDeclaredWindowLog = 23; // 2^23 bytes = 8 MiB.

    using FilePtr = std::unique_ptr<std::FILE, decltype(&std::fclose)>;

    struct DStreamGuard
    {
        ZSTD_DStream* stream;
        ~DStreamGuard()
        {
            ZSTD_freeDStream(stream);
        }
    };

    // Atomically replaces targetPath's content with sourcePath's, keeping targetPath's own name.
    // Both files must already be closed. Requires sourcePath and targetPath to live on the same
    // filesystem for the POSIX branch's atomicity to actually hold -- true here, since the caller
    // always creates sourcePath under the same spoolDir that produced targetPath.
    bool replaceFile(const std::string& sourcePath, const std::string& targetPath)
    {
#ifdef WIN32
        return MoveFileExA(sourcePath.c_str(), targetPath.c_str(), MOVEFILE_REPLACE_EXISTING) != 0;
#else
        return std::rename(sourcePath.c_str(), targetPath.c_str()) == 0;
#endif
    }
} // namespace

std::optional<uint64_t>
ZstdFileDecompressor::decompress(const std::string& pathToReplace, uint64_t maxDecompressedBytes,
                                 const std::string& spoolDir, const std::atomic<bool>* abortFlag)
{
    FilePtr source {std::fopen(pathToReplace.c_str(), "rb"), std::fclose};

    if (!source)
    {
        return std::nullopt;
    }

    std::array<uint8_t, FILE_CHUNK> inChunk {};
    size_t bytesRead = std::fread(inChunk.data(), 1, inChunk.size(), source.get());

    if (bytesRead == 0)
    {
        // Zero bytes is not a valid (empty) frame, it is simply not a frame at all -- matches the
        // manager's zstdDecoder.cpp's own rule for an empty compressed buffer.
        return std::nullopt;
    }

    if (abortFlag != nullptr && abortFlag->load())
    {
        return std::nullopt;
    }

    std::string destPath;
    const int destFd = createExclusiveTempFile(spoolDir, "hc_zstd_dec_", destPath);

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
        (void)std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: fdopen() on a just-opened fd doesn't fail in practice.
    }

    ZSTD_DStream* dstream = ZSTD_createDStream();

    if (dstream == nullptr)
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: allocation failure only.
    }

    const DStreamGuard guard {dstream};

    if (ZSTD_isError(ZSTD_initDStream(dstream)))
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: cannot fail right after ZSTD_createDStream().
    }

    if (ZSTD_isError(ZSTD_DCtx_setParameter(dstream, ZSTD_d_windowLogMax, kMaxDeclaredWindowLog)))
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: a stable, in-range parameter cannot be rejected.
    }

    std::array<uint8_t, FILE_CHUNK> outChunk {};
    uint64_t totalOut = 0;
    size_t frameRemaining = 0;

    // Feeds one input chunk through the decoder, writing whatever plain bytes it produces.
    // Returns false on any error: a zstd decode error, the output crossing
    // maxDecompressedBytes, or a write failure.
    const auto feedChunk = [&](const uint8_t* data, size_t size)
    {
        ZSTD_inBuffer input {data, size, 0};

        while (input.pos < input.size)
        {
            ZSTD_outBuffer output {outChunk.data(), outChunk.size(), 0};
            const size_t ret = ZSTD_decompressStream(dstream, &output, &input);

            if (ZSTD_isError(ret))
            {
                return false;
            }

            // 0 means the frame is fully decoded; any other value is only meaningful once input
            // is exhausted (checked after the outer loop below), same as zstdDecoder.cpp's own
            // frameRemaining tracking.
            frameRemaining = ret;

            if (output.pos == 0)
            {
                continue;
            }

            // (totalOut <= maxDecompressedBytes always, by this same check on every prior
            // iteration, so the subtraction below never underflows -- same style as
            // curlHandle.cpp's fileWriteTrampoline byte-cap check.)
            if (maxDecompressedBytes != 0 && output.pos > maxDecompressedBytes - totalOut)
            {
                return false; // Cap exceeded -- abort before writing past it, not after.
            }

            if (std::fwrite(outChunk.data(), 1, output.pos, dest.get()) != output.pos)
            {
                return false; // LCOV_EXCL_LINE: write failure is not reproducible in tests.
            }

            totalOut += output.pos;
        }

        return true;
    };

    if (!feedChunk(inChunk.data(), bytesRead))
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt;
    }

    while ((bytesRead = std::fread(inChunk.data(), 1, inChunk.size(), source.get())) > 0)
    {
        if (abortFlag != nullptr && abortFlag->load())
        {
            (void)std::remove(destPath.c_str());
            return std::nullopt;
        }

        if (!feedChunk(inChunk.data(), bytesRead))
        {
            (void)std::remove(destPath.c_str());
            return std::nullopt;
        }
    }

    if (std::ferror(source.get()))
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt;
    }

    // frameRemaining != 0 after all input has been fed means the frame is incomplete (more input
    // would be required to finish it) -- a truncated transfer.
    if (frameRemaining != 0)
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt;
    }

    // Zero plain bytes out of a non-empty input is not a config: it means the response carried no
    // real frame at all, only zstd frames that decode to nothing (skippable frames, which
    // ZSTD_decompressStream() consumes silently, or an empty-payload frame). Refuse rather than
    // rename an empty file over the caller's download.
    if (totalOut == 0)
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt;
    }

    dest.reset();   // Close (flush to disk) before the rename.
    source.reset(); // Close before replacing the file it was reading (required on Windows).

    if (!replaceFile(destPath, pathToReplace))
    {
        (void)std::remove(destPath.c_str());
        return std::nullopt; // LCOV_EXCL_LINE: rename failure (cross-device, permissions) not reproducible in tests.
    }

    return totalOut;
}
