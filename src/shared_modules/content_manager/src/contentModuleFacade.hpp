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

#ifndef _CONTENT_MODULE_IMPLEMENTATION_HPP
#define _CONTENT_MODULE_IMPLEMENTATION_HPP

#include "contentIndexer.hpp"
#include "contentProvider.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTopicSpec.hpp"
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
 * ### Why there is no connection here
 *
 * The library never builds an indexer connection (D1): each registration is handed the host's, as a
 * `content_manager::IContentIndexer`. A host therefore runs one connector stack — one health
 * monitor, one keystore read — however many topics it registers, and an indexer outage is reported
 * once, by the host's own connector.
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
     * @param spec The parsed registration (D2).
     * @param sink Where the content goes.
     * @param tokenStore Host-supplied token store; may be null.
     * @param indexer The host's indexer. Required.
     * @throws std::runtime_error if the topic is already registered.
     * @throws std::invalid_argument if the configuration is not usable or @p indexer is null.
     */
    void addProvider(const std::string& name,
                     const content_manager::TopicSpec& spec,
                     std::shared_ptr<content_manager::IContentSink> sink,
                     std::shared_ptr<content_manager::IContentIndexer> indexer,
                     std::shared_ptr<content_manager::IContentTokenStore> tokenStore = nullptr);

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

private:
    std::unordered_map<std::string, std::unique_ptr<ContentProvider>> m_providers;
    mutable std::shared_mutex m_mutex;
};

#endif //_CONTENT_MODULE_IMPLEMENTATION_HPP
