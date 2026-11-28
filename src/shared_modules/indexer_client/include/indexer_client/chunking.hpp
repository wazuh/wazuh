/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_CHUNKING_HPP
#define _INDEXER_CLIENT_CHUNKING_HPP

// Consumer-side helpers to cut writes into Groups by quota. Header-only: nothing here is
// exported by the library. The consumers keep their own staging machines (barriers, deadlines); only the arithmetic
// they shared lives here.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "types.hpp"

namespace indexer_client
{
    /// Upper bound of an action line's fixed bytes (`{"update":{"_index":"` + `","_id":"` + `"}}\n` = 34,
    /// `src/write/encoding.cpp` INDEX/DELETE/UPDATE_PREFIX, ID_INFIX, ACTION_SUFFIX), with room to spare.
    constexpr std::size_t CHUNK_ACTION_FRAME_BYTES {64};

    /// Upper bound of the scripted line's fixed bytes of an IndexVersionedScript (`encoding.cpp` SCRIPT_OPEN,
    /// V1_GUARD_SOURCE, SCRIPT_PARAMS, SCRIPT_VERSION, SCRIPT_DOC, SCRIPT_UPSERT, SCRIPT_TAIL: about 260 B).
    constexpr std::size_t CHUNK_VERSIONED_FRAME_BYTES {512};

    /**
     * @brief Per-worker chunk cap: 0.8 · quota / (2 · lanes), so every lane can hold an open and a pending chunk.
     *
     * @param quotaBytes The bucket's quota.
     * @param lanes Workers sharing the bucket; 0 counts as 1.
     * @return The cap, never below 1.
     */
    inline std::size_t chunkCap(std::size_t quotaBytes, std::size_t lanes)
    {
        const auto share =
            static_cast<double>(quotaBytes) * 0.8 / (2.0 * static_cast<double>(std::max<std::size_t>(lanes, 1)));
        return std::max<std::size_t>(static_cast<std::size_t>(share), 1);
    }

    /// The `_id` as `encoding.cpp` escapes it, bounded from above: `"` and `\` take 2 bytes, any other control
    /// character at most 6 (`\u00XX`).
    inline std::size_t escapedSizeBound(std::string_view id)
    {
        std::size_t size = 0;
        for (const char c : id)
        {
            if (c == '"' || c == '\\')
            {
                size += 2;
            }
            else if (static_cast<unsigned char>(c) < 0x20)
            {
                size += 6;
            }
            else
            {
                ++size;
            }
        }
        return size;
    }

    /**
     * @brief What the library will charge for @p op (payload + the per-op result reserve), never less.
     *
     * Delete: the action line alone. IndexVersionedScript: everything lives in the head, the document twice plus the
     * v1 script. Any other kind: action line + body + '\n' + the body's heap slack (taken as its whole capacity).
     *
     * @param op The operation, as it will be added.
     * @param resultReserve Bytes the library charges per op besides its payload (`src/write/bucket.hpp`
     *                      RESULT_RESERVE).
     */
    inline std::size_t estimateCharge(const Op& op, std::uint64_t resultReserve)
    {
        std::size_t bytes = CHUNK_ACTION_FRAME_BYTES + op.index.size() + escapedSizeBound(op.id) +
                            static_cast<std::size_t>(resultReserve);
        switch (op.kind)
        {
            case Op::Kind::Delete: break;
            case Op::Kind::IndexVersionedScript:
                bytes += CHUNK_VERSIONED_FRAME_BYTES + op.version.size() + 2 * op.body.size();
                break;
            default: bytes += op.body.capacity() + 1; break;
        }
        return bytes;
    }
} // namespace indexer_client

#endif // _INDEXER_CLIENT_CHUNKING_HPP
