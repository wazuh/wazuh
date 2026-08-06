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
#include <functional>
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
        Malformed, ///< Not a valid/complete zstd frame (bad magic, truncated, unreadable header, etc.).
        TooLarge,  ///< A reservation callback refused: the window or the growing output didn't fit.
    };

    /**
     * @brief Try to reserve @p additionalBytes more against some caller-owned live budget.
     *
     * Tracks the memory the decompressed output OCCUPIES, so the caller can hold it as a REAL
     * reservation against a shared in-flight byte budget instead of checking a static number nobody
     * actually holds. Must be safe to call repeatedly with growing cumulative totals.
     *
     * What is reserved is the output buffer's CAPACITY, not the bytes written so far: those are the
     * bytes actually taken from the allocator. zstdDecode() only ever grows capacity right after a
     * matching reservation is granted, so the granted total always covers what is really allocated
     * -- charging written bytes instead would undercount by however much the buffer over-allocates.
     *
     * @return true if granted, false if the budget doesn't have that much room right now -- causes
     *         zstdDecode() to abort with ZstdDecodeError::TooLarge.
     */
    using ReserveMoreFn = std::function<bool(std::size_t additionalBytes)>;

    /**
     * @brief Try to reserve @p bytes for the decoder's internal window buffer.
     *
     * Called exactly once, before any decompression starts, with the amount of memory THIS frame's
     * header actually declares it needs (read straight off the frame, not a worst-case bound) --
     * so a shared budget can account for the window as real memory rather than merely capping it.
     * The window is freed before zstdDecode() returns, so the caller should release this
     * reservation on return rather than holding it alongside the decompressed output.
     *
     * @return true if granted, false to refuse the frame -- causes zstdDecode() to abort with
     *         ZstdDecodeError::TooLarge without decompressing anything.
     */
    using ReserveWindowFn = std::function<bool(std::size_t bytes)>;

    /**
     * @brief Decompress a zstd-encoded buffer, with both of the decoder's memory costs accounted
     *        for as real reservations against a caller-owned budget.
     *
     * Unlike gzip/DEFLATE (fixed 32 KiB window by spec), a zstd frame's header declares its own
     * window size -- memory the decoder allocates up front, before producing any output. This reads
     * that declared size off the frame header and hands it to @p reserveWindow, so the caller
     * reserves exactly what this frame needs instead of a blanket worst case. A frame is refused
     * outright if @p reserveWindow says no.
     *
     * The output buffer is reserved through @p reserveMore, always BEFORE its capacity actually
     * grows, so the granted total covers what is really allocated (see ReserveMoreFn). A frame
     * header normally also declares its decompressed size, in which case that is charged once and
     * the buffer is sized to it exactly -- one allocation, no over-allocation, nothing to copy as
     * it fills. A frame that omits the size (or declares one lower than it really decodes to) falls
     * back to growing in blocks, still charged before each growth.
     *
     * Because both costs are REAL reservations the caller controls, concurrent callers genuinely
     * contend for the same pool -- rather than each reading the same "free" snapshot and all
     * proceeding at once, together overshooting it.
     *
     * Note that a frame declaring a large size is refused up front on that declaration alone, even
     * if it would have decoded to less: the declaration is what the decoder is asked to allocate for.
     *
     * @param compressed    Zstd-encoded input bytes (the exact wire body).
     * @param reserveWindow Called once with this frame's declared window size; see ReserveWindowFn.
     * @param reserveMore   Called to reserve output-buffer capacity; see ReserveMoreFn.
     * @return The decompressed bytes on success, or the failure reason.
     */
    std::variant<std::string, ZstdDecodeError> zstdDecode(std::string_view compressed,
                                                          const ReserveWindowFn& reserveWindow,
                                                          const ReserveMoreFn& reserveMore);

} // namespace remoted::common

#endif // _REMOTED_COMMON_ZSTD_DECODER_HPP
