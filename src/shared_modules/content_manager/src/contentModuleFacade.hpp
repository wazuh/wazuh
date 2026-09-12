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

#ifndef _CONTENT_MODULE_IMPLEMENTATION_HPP
#define _CONTENT_MODULE_IMPLEMENTATION_HPP

#include "components/indexerQueryPort.hpp"
#include "contentProvider.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include "singleton.hpp"
#include <cstdarg>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

/**
 * @brief The module's single registry of topics — and of the indexer sessions they share.
 *
 * ### Why the session registry lives here
 *
 * A connector's constructor resolves credentials, merges CA bundles, runs a synchronous health
 * check against every host and starts its own health-monitor thread. The previous code built a
 * fresh one **per PIT operation** — five call sites plus one per slice — which was merely wasteful
 * for VD's single topic but multiplies by the number of topics, and the Engine has eight of them by
 * default, held alongside its own event-indexing connector.
 *
 * `IndexerSession` exists precisely for "this process holds more than one connector": every
 * connector built from a session adopts that session's single monitor. The registry is keyed by a
 * fingerprint of the connection settings, so registrations that talk to the same indexer with the
 * same credentials share one session and one monitor, and registrations that do not are kept apart
 * — a session's monitor only knows the hosts it was built with.
 *
 * Sessions are held weakly: the last port using one releases it.
 */
class ContentModuleFacade final : public Singleton<ContentModuleFacade>
{
public:
    /**
     * @brief Install the log function used by everything inside the module.
     *
     * @param logFunction Host log function.
     */
    void
    start(const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
              logFunction);

    /**
     * @brief Drop every registration.
     */
    void stop();

    /**
     * @brief Unregister one topic.
     *
     * @param name Topic name.
     */
    void removeProvider(const std::string& name);

    /**
     * @brief Register one topic.
     *
     * @param name Topic name.
     * @param parameters Registration parameters.
     * @param sink Where the content goes.
     * @param tokenStore Host-supplied token store; may be null.
     * @param port Indexer access. When null, one is built over a shared session derived from
     *             `parameters.configData.indexer`. Tests pass a fake here.
     * @throws std::runtime_error if the topic is already registered.
     * @throws std::invalid_argument if the configuration is not usable.
     */
    void addProvider(const std::string& name,
                     const nlohmann::json& parameters,
                     std::shared_ptr<content_manager::IContentSink> sink,
                     std::shared_ptr<content_manager::IContentTokenStore> tokenStore = nullptr,
                     std::shared_ptr<IIndexerQueryPort> port = nullptr);

    /**
     * @brief Start the library's driver thread for a topic.
     *
     * @param name Topic name.
     * @param interval Interval, in seconds.
     */
    void startScheduling(const std::string& name, size_t interval);

    /**
     * @brief Publish a topic on the on-demand lane.
     *
     * @param name Topic name.
     */
    void startOndemand(const std::string& name);

    /**
     * @brief Change a topic's driver interval.
     *
     * @param name Topic name.
     * @param interval New interval, in seconds.
     */
    void changeSchedulerInterval(const std::string& name, size_t interval);

    /**
     * @brief Run one cycle for a topic.
     *
     * @param name Topic name.
     * @param request What the caller wants.
     * @return The outcome. `CycleStatus::FailedConfig` when the topic is not registered.
     */
    content_manager::CycleOutcome runOnce(const std::string& name, content_manager::RunRequest request) noexcept;

    /**
     * @brief The token in force for a topic.
     *
     * @param name Topic name.
     * @return The token, or "" when the topic is unknown or has none.
     */
    std::string currentToken(const std::string& name) const noexcept;

    /**
     * @brief Ask a topic's in-flight cycle to wind down.
     *
     * @param name Topic name.
     */
    void requestStop(const std::string& name) noexcept;

    /**
     * @brief The identity of an indexer connection: everything a session is built from.
     *
     * Two registrations share a session only when these match exactly. `monitoring_interval_seconds`
     * is part of it because a session's monitor is built with one value and every connector on it
     * inherits that value, so two registrations asking for different periods must not be merged.
     *
     * Public because it is the rule this class's sharing behaviour rests on, and it is worth
     * asserting directly rather than only through the side effect of how many monitor threads a
     * process ends up with.
     *
     * @param indexerConfig The `configData.indexer` object.
     * @return A canonical fingerprint string.
     */
    static std::string fingerprint(const nlohmann::json& indexerConfig);

private:
    /**
     * @brief Get, or lazily create, the session for a set of connection settings.
     *
     * @param indexerConfig The `configData.indexer` object.
     * @return The shared session.
     */
    std::shared_ptr<IndexerSession> sessionFor(const nlohmann::json& indexerConfig);

    std::unordered_map<std::string, std::unique_ptr<ContentProvider>> m_providers;
    /// Weak on purpose: a session lives exactly as long as some port still needs it.
    std::unordered_map<std::string, std::weak_ptr<IndexerSession>> m_sessions;
    mutable std::shared_mutex m_mutex;
};

#endif //_CONTENT_MODULE_IMPLEMENTATION_HPP
