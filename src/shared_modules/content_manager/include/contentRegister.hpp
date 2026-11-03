/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CONTENT_REGISTER_HPP
#define _CONTENT_REGISTER_HPP

#include "contentExport.hpp"
#include "contentIndexer.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTopicSpec.hpp"
#include "contentTypes.hpp"
#include <functional>
#include <memory>
#include <string>

class TopicDriver;

/**
 * @brief One registered content topic: its configuration, its sink and its token.
 *
 * A host that owns a scheduler (the Engine) registers without `schedule.intervalSeconds` and calls
 * @ref runOnce from its own task. A host that does not (the vulnerability scanner) sets it and gets
 * a driver thread that runs a cycle at start, then on the interval, and runs @ref requestRun's
 * requests in between.
 */
class EXPORTED ContentRegister final
{
public:
    /**
     * @brief Register a topic.
     *
     * @param topicName Topic name, carried on every log line and sink call.
     * @param spec The registration (contentTopicSpec.hpp).
     * @param sink Destination for the downloaded content. Must not be null.
     * @param indexer The host's indexer (contentIndexer.hpp, D1). Must not be null. Held for the
     *                registration's whole life.
     * @param tokenStore Where the change-detection token lives. When null, the library keeps it in a
     *                   RocksDB under `state.databasePath`; with no `databasePath` either, the topic is
     *                   tokenless and every cycle is a full reload.
     *
     * @throws std::invalid_argument if the spec is invalid (naming the field), or the sink or the
     *         indexer is null.
     * @throws std::runtime_error if the token database cannot be opened, even after a rebuild.
     */
    ContentRegister(std::string topicName,
                    const content_manager::TopicSpec& spec,
                    std::shared_ptr<content_manager::IContentSink> sink,
                    std::shared_ptr<content_manager::IContentIndexer> indexer,
                    std::shared_ptr<content_manager::IContentTokenStore> tokenStore = nullptr);

    /**
     * @brief Unregister the topic.
     *
     * Stops the driver thread, answers a pending @ref requestRun with `ShuttingDown`, and waits for
     * an in-flight cycle, so no callback into the sink can be running once this returns. Two
     * consequences, both deadlocks if ignored: release any lock the sink also takes before destroying
     * the registration, and never destroy it from inside its own sink.
     */
    ~ContentRegister();

    ContentRegister(const ContentRegister&) = delete;
    ContentRegister& operator=(const ContentRegister&) = delete;

    /**
     * @brief Run exactly one content cycle on the calling thread.
     *
     * Bounded: every gate is single-pass, so a deferred cycle returns with `retryAfter` instead of
     * waiting. Never throws. If a cycle of this topic is already running, returns
     * `SkippedAlreadyRunning` at once ("nothing ran"), which is distinct from `SkippedStopRequested`.
     *
     * @param req What the caller wants from this cycle.
     * @return What the cycle did, and how long the caller should wait before the next one.
     */
    content_manager::CycleOutcome runOnce(content_manager::RunRequest req = {}) noexcept;

    /**
     * @brief Ask the driver thread to run a cycle now.
     *
     * Never blocks, so it is safe from a transport I/O thread. A request that cannot be queued — a
     * cycle running or already requested, a stopping topic, a topic without an interval — is answered
     * inline; otherwise the driver thread runs it and answers on that thread.
     *
     * @param req What the cycle should do.
     * @param completion Invoked exactly once with the result. May be empty.
     */
    void requestRun(content_manager::RunRequest req,
                    std::function<void(content_manager::OnDemandResult)> completion) noexcept;

    /**
     * @brief The token in force for this topic.
     *
     * @return The stored token, or "" when nothing has been committed yet.
     */
    std::string currentToken() const noexcept;

    /**
     * @brief Stop this topic for good.
     *
     * An in-flight cycle winds down at its next checkpoint, and every later cycle returns
     * `SkippedStopRequested`. Used by hosts that tear down in two steps: stop everything, then
     * destroy.
     */
    void requestStop() noexcept;

private:
    std::unique_ptr<TopicDriver> m_driver;
};

#endif // _CONTENT_REGISTER_HPP
