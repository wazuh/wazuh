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

#include "write/sink.hpp"

#include <atomic>
#include <limits>
#include <utility>

#include "write/writer.hpp"

// The production sink of stage E3a (plan 18 I63): there is no bulk sender yet (E3b), so every op of every batch is
// resolved Failed(Unavailable) at once, which is what the E1 stub writer answered.

namespace indexer_client::detail::write
{
    namespace
    {
        class UnavailableSink final : public BatchSink
        {
        public:
            explicit UnavailableSink(std::weak_ptr<WritePath> path)
                : m_path(std::move(path))
            {
            }

            std::size_t capacity() override
            {
                return std::numeric_limits<std::size_t>::max();
            }

            void dispatch(Batch batch) override
            {
                if (m_stopped.load())
                {
                    return; // The shutdown sweep resolves what the scheduler still hands over.
                }
                auto path = m_path.lock();
                if (!path)
                {
                    return;
                }
                for (const auto& op : batch.ops)
                {
                    OpResult result;
                    result.status = Status::Failed;
                    result.cause = Cause::Unavailable;
                    result.reason = "no bulk sender yet (E3b)";
                    path->resolve(op, std::move(result));
                }
            }

            void stop() override
            {
                m_stopped.store(true);
            }

        private:
            std::weak_ptr<WritePath> m_path;
            std::atomic<bool> m_stopped {false};
        };
    } // namespace

    std::shared_ptr<BatchSink> makeUnavailableSink(std::weak_ptr<WritePath> path)
    {
        return std::make_shared<UnavailableSink>(std::move(path));
    }
} // namespace indexer_client::detail::write
