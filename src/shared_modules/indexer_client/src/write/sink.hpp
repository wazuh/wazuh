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

// Where the scheduler hands batches (stage E3a, plan 18 I63). E3b replaces the production sink with the bulk sender;
// E5's limiter becomes its capacity.

#include <cstddef>
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
        /// Takes the batch (loop 0). Every op is resolved exactly once through WritePath::resolve, from any thread.
        virtual void dispatch(Batch batch) = 0;
        /// After stop() no batch is accepted; batches the sink still holds are resolved Dropped(Shutdown) by the
        /// runtime's sweep (resolution is first-wins, so the sink may still race it harmlessly).
        virtual void stop() = 0;
    };

    /// Production sink of E3a: every op Failed(Unavailable) (today's stub semantics), unbounded capacity.
    std::shared_ptr<BatchSink> makeUnavailableSink(std::weak_ptr<WritePath> path);
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_SINK_HPP
