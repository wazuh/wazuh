/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_REGISTER_HPP
#define _CONTENT_REGISTER_HPP

#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include <json.hpp>
#include <memory>
#include <string>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/**
 * @brief One registered content topic: its configuration, its sink and its token.
 *
 * The library is *pull*-driven. A host that already owns a scheduler (the Engine) constructs a
 * registration without an `interval` and calls @ref runOnce from its own task; a host that does not
 * (the vulnerability scanner) passes `interval` and gets the library's own driver thread, which
 * calls the same @ref runOnce.
 *
 * Expected @p parameters shape:
 * @code{.jsonc}
 * {
 *   "topicName": "vulnerability_feed_manager",
 *   "interval": 3600,          // optional: present => the library spawns a driver thread
 *   "ondemand": true,          // optional: register the topic on the on-demand lane
 *   "configData": {
 *     "consumerName": "Wazuh VulnerabilityDetector",   // required, becomes the HTTP User-Agent
 *     "changeDetection": "cursor",                     // required: "cursor" | "hash"
 *     "databasePath": "queue/vd/vd_updater/rocksdb",   // optional: enables the built-in token store
 *     "resetStateOnRegister": false,                   // optional: clear the token at construction
 *     "consumerRetryIntervalSeconds": 60,              // optional, default 60
 *     "indexer": { ... }                               // hosts, ssl, auth + the per-topic query spec
 *   }
 * }
 * @endcode
 */
class EXPORTED ContentRegister final
{
public:
    /**
     * @brief Register a topic.
     *
     * @param topicName Unique topic name. Also the key of the on-demand route.
     * @param parameters Registration parameters (see the class documentation).
     * @param sink Destination for the downloaded content. Must not be null.
     * @param tokenStore Where the change-detection token lives. When null, the library builds one
     *                   over `configData.databasePath`; passing null with no `databasePath` leaves
     *                   the topic tokenless, i.e. every cycle is a full reload.
     * @param contractVersion Leave at its default. Compiled into the caller so a host built against
     *                        a stale `contentTypes.hpp` is refused instead of misreading a struct.
     *
     * @throws std::invalid_argument if the configuration is invalid, the sink is null, or the
     *         contract version does not match the one built into the library.
     * @throws std::runtime_error if the topic is already registered.
     */
    explicit ContentRegister(std::string topicName,
                             const nlohmann::json& parameters,
                             std::shared_ptr<content_manager::IContentSink> sink,
                             std::shared_ptr<content_manager::IContentTokenStore> tokenStore = nullptr,
                             std::uint32_t contractVersion = content_manager::CONTRACT_ABI_VERSION);

    /**
     * @brief Unregister the topic.
     *
     * Blocks until any in-flight cycle for this topic has finished and its on-demand route has been
     * withdrawn, so no callback into the sink can be running once this returns.
     *
     * Two consequences of that guarantee, both of which are deadlocks if ignored:
     *  - a host that holds a lock the sink also takes must release it before destroying the
     *    registration;
     *  - a registration must never be destroyed from inside its own sink callback. This waits for
     *    the cycle that callback belongs to, so it would be waiting on itself.
     */
    ~ContentRegister();

    ContentRegister(const ContentRegister&) = delete;
    ContentRegister& operator=(const ContentRegister&) = delete;

    /**
     * @brief Run exactly one content cycle, synchronously.
     *
     * Bounded: every gate is single-pass, so this returns in roughly the time one pass over the
     * source takes and never parks the calling thread on a poll. Never throws.
     *
     * Mutually exclusive per topic: if a cycle for this topic is already running (scheduled or
     * on-demand), this returns immediately with `CycleStatus::SkippedAlreadyRunning` rather than
     * running a second one concurrently. That status is distinct from `SkippedStopRequested` on
     * purpose — a caller that folds a cycle's outcome into its own state must be able to tell "I
     * observed nothing because nothing ran" from "I observed a completed no-op", and the two have
     * opposite meanings for whatever the caller reads afterwards.
     *
     * @param req What the caller wants from this cycle.
     * @return What the cycle did, and how long the caller should wait before the next one.
     */
    content_manager::CycleOutcome runOnce(content_manager::RunRequest req = {}) noexcept;

    /**
     * @brief The token in force for this topic.
     *
     * @return The stored token, or "" when nothing has been committed yet.
     */
    std::string currentToken() const noexcept;

    /**
     * @brief Ask any in-flight cycle to wind down at the next checkpoint.
     */
    void requestStop() noexcept;

    /**
     * @brief Change the driver thread's interval.
     *
     * No-op when the registration was created without an `interval`.
     *
     * @param newInterval New interval, in seconds.
     */
    void changeSchedulerInterval(size_t newInterval);

private:
    std::string m_name;
};

#endif // _CONTENT_REGISTER_HPP
