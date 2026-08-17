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

#include "zstdDecoder.hpp"

// ZSTD_getFrameHeader() and ZSTD_decodingBufferSize_min() -- which expose how much memory a frame
// will actually make the decoder allocate -- live behind this opt-in. We rely on them to reserve
// exactly that much against the shared in-flight budget instead of a blanket worst-case bound;
// capping alone would leave the window buffer as real memory nothing accounts for. It is nominally
// zstd's "experimental" surface, but the risk here is contained: we vendor and statically link a
// pinned zstd (src/external/zstd), so any signature change surfaces at build time on a version
// bump rather than silently at runtime.
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include <array>
#include <limits>

namespace remoted::common
{

    namespace
    {
        constexpr std::size_t kChunkSize = 64U * 1024U;
    } // namespace

    std::variant<std::string, ZstdDecodeError>
    zstdDecode(std::string_view compressed, const ReserveWindowFn& reserveWindow, const ReserveMoreFn& reserveMore)
    {
        // Zero bytes is not a valid (empty) frame, it is simply not a frame at all.
        if (compressed.empty())
        {
            return ZstdDecodeError::Malformed;
        }

        // Read the frame header FIRST, before allocating any decoder state: it tells us how much
        // memory this specific frame will make the decoder reserve up front, which is what we hand
        // to reserveWindow(). A truncated/garbage header (>0 means "need more input", or an error
        // code) is rejected here without touching the budget at all.
        ZSTD_FrameHeader header {};
        const std::size_t headerResult = ZSTD_getFrameHeader(&header, compressed.data(), compressed.size());
        if (headerResult != 0 || header.frameType != ZSTD_frame)
        {
            return ZstdDecodeError::Malformed;
        }

        // What the decoder will really allocate for its window/output buffers, per zstd's own
        // sizing helper -- not just header.windowSize, which is only part of that total. Guard the
        // 64-bit -> size_t narrowing: on a 32-bit build a frame could legitimately declare more
        // than size_t can hold, which we can't satisfy regardless.
        const unsigned long long bufferSize =
            ZSTD_decodingBufferSize_min(header.windowSize, header.frameContentSize);
        if (ZSTD_isError(static_cast<std::size_t>(bufferSize)) ||
            bufferSize > std::numeric_limits<std::size_t>::max())
        {
            return ZstdDecodeError::TooLarge;
        }

        if (!reserveWindow(static_cast<std::size_t>(bufferSize)))
        {
            return ZstdDecodeError::TooLarge;
        }

        ZSTD_DStream* dstream = ZSTD_createDStream();
        if (dstream == nullptr)
        {
            return ZstdDecodeError::Malformed;
        }

        // RAII: guarantees ZSTD_freeDStream() on every return path below, including the early ones.
        struct DStreamGuard
        {
            ZSTD_DStream* stream;
            ~DStreamGuard()
            {
                ZSTD_freeDStream(stream);
            }
        } guard {dstream};

        if (ZSTD_isError(ZSTD_initDStream(dstream)))
        {
            return ZstdDecodeError::Malformed;
        }

        ZSTD_inBuffer input {compressed.data(), compressed.size(), 0};
        std::string output;
        std::array<char, kChunkSize> chunk {};
        std::size_t frameRemaining = 0;

        // Bytes reserved for `output`'s capacity so far. Kept equal to output.capacity() by
        // growOutputCapacity() below, so the caller's budget tracks memory really taken from the
        // allocator -- not the smaller "bytes written" figure, which the buffer's own
        // over-allocation would leave the budget systematically under-counting.
        std::size_t reservedCapacity = 0;

        // Reserve, then grow capacity to exactly the reserved amount. Reserving first is what keeps
        // the budget honest: capacity never exceeds what was granted.
        const auto growOutputCapacity = [&output, &reservedCapacity, &reserveMore](std::size_t target)
        {
            if (target <= reservedCapacity)
            {
                return true;
            }
            if (!reserveMore(target - reservedCapacity))
            {
                return false;
            }
            reservedCapacity = target;
            output.reserve(reservedCapacity);
            return true;
        };

        // The frame normally declares its decompressed size: charge and size the buffer to exactly
        // that, once. One allocation, no over-allocation, and nothing to copy as it fills. A frame
        // that omits the size falls back to the block growth in the loop below.
        if (header.frameContentSize != ZSTD_CONTENTSIZE_UNKNOWN &&
            header.frameContentSize <= std::numeric_limits<std::size_t>::max() &&
            !growOutputCapacity(static_cast<std::size_t>(header.frameContentSize)))
        {
            return ZstdDecodeError::TooLarge;
        }

        while (input.pos < input.size)
        {
            ZSTD_outBuffer out {chunk.data(), chunk.size(), 0};
            const std::size_t ret = ZSTD_decompressStream(dstream, &out, &input);
            if (ZSTD_isError(ret))
            {
                return ZstdDecodeError::Malformed;
            }
            frameRemaining = ret;

            if (out.pos > 0)
            {
                // Only reached for a frame that declares NO decompressed size (streaming
                // compression with no pledged size); a declared size was already covered above.
                // Grow in doubling blocks rather than per chunk, so this doesn't mean a reservation
                // call -- and a reallocation -- for every 64 KiB.
                const std::size_t needed = output.size() + out.pos;
                if (needed > reservedCapacity)
                {
                    std::size_t target = reservedCapacity < kChunkSize ? kChunkSize : reservedCapacity;
                    while (target < needed)
                    {
                        // Guard the doubling: past this point grow to exactly what's needed instead.
                        if (target > std::numeric_limits<std::size_t>::max() / 2)
                        {
                            target = needed;
                            break;
                        }
                        target *= 2;
                    }
                    // The caller's budget may also be shrinking concurrently (other requests
                    // reserving bytes of their own), so this is a live contention point.
                    if (!growOutputCapacity(target))
                    {
                        return ZstdDecodeError::TooLarge;
                    }
                }
                output.append(chunk.data(), out.pos);
            }
        }

        // frameRemaining != 0 after all input has been fed means the frame is incomplete (more
        // input would be required to finish it) -- a truncated stream.
        if (frameRemaining != 0)
        {
            return ZstdDecodeError::Malformed;
        }

        return output;
    }

} // namespace remoted::common
