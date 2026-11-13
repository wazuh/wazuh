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

#ifndef _INDEXER_CLIENT_WRITE_SINK_HPP
#define _INDEXER_CLIENT_WRITE_SINK_HPP

// Where the scheduler hands batches. The production sink is the bulk sender;
// its limiter (sender.hpp) provides the capacity and the batchLimit.

#include <cstddef>
#include <cstdint>
#include <memory>

#include "write/bucket.hpp"

namespace indexer_client::detail::write
{
    class WritePath;

    class BatchSink
    {
    public:
        virtual ~BatchSink() = default;

        /// Batches the sink accepts now (loop 0 reads it before each dispatch). 0 stops the scheduler until the sink
        /// calls WritePath::sinkReady().
        virtual std::size_t capacity() = 0;
        /// Wire bytes the next batch should not exceed (loop 0, read before each slice); 0 = no limit. Never
        /// applied to the first op of a batch.
        virtual std::uint64_t batchLimit()
        {
            return 0;
        }
        /// Cancels the transfers in flight of `bucket`'s batches (awaitClosed's sweep outside a runtime
        /// shutdown); their late results are Ignore. No-op by default.
        virtual void cancelBucket(const Bucket& /*bucket*/) {}
        /// Takes the batch (loop 0). Every op is resolved exactly once through WritePath::resolve, from any thread.
        virtual void dispatch(Batch batch) = 0;
        /// After stop() no batch is accepted; batches the sink still holds are resolved Dropped(Shutdown) by the
        /// runtime's sweep (resolution is first-wins, so the sink may still race it harmlessly).
        virtual void stop() = 0;
    };

    /// Fallback sink: every op Failed(Unavailable) (today's stub semantics), unbounded capacity.
    std::shared_ptr<BatchSink> makeUnavailableSink(std::weak_ptr<WritePath> path);
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_SINK_HPP
