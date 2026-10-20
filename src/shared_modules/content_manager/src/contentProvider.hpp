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

#ifndef _CONTENT_PROVIDER_HPP
#define _CONTENT_PROVIDER_HPP

#include "action.hpp"
#include <json.hpp>
#include <memory>
#include <string>
#include <utility>

/**
 * @brief One registered topic, as the facade sees it.
 */
class ContentProvider final
{
public:
    /**
     * @brief Register a topic.
     *
     * @param topicName Topic name.
     * @param spec The parsed registration.
     * @param sink Where the content goes.
     * @param tokenStore Host-supplied token store; may be null.
     * @param port Indexer access.
     */
    ContentProvider(const std::string& topicName,
                    const content_manager::TopicSpec& spec,
                    std::shared_ptr<content_manager::IContentSink> sink,
                    std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                    std::shared_ptr<content_manager::IContentIndexer> port)
        : m_action {std::make_unique<Action>(topicName, spec, std::move(sink), std::move(tokenStore), std::move(port))}
    {
    }

    /// @copydoc Action::startActionScheduler
    void startActionScheduler(const size_t interval)
    {
        m_action->startActionScheduler(interval);
    }

    /// @copydoc Action::registerActionOnDemand
    void startOnDemandAction()
    {
        m_action->registerActionOnDemand();
    }

    /// @copydoc Action::changeSchedulerInterval
    void changeSchedulerInterval(const size_t interval)
    {
        m_action->changeSchedulerInterval(interval);
    }

    /// @copydoc Action::tryBeginRun
    bool tryBeginRun() noexcept
    {
        return m_action->tryBeginRun();
    }

    /// @copydoc Action::runClaimed
    content_manager::CycleOutcome runClaimed(const content_manager::RunRequest& request) noexcept
    {
        return m_action->runClaimed(request);
    }

    /// @copydoc Action::waitForIdle
    void waitForIdle() noexcept
    {
        m_action->waitForIdle();
    }

    /// @copydoc Action::currentToken
    std::string currentToken() const noexcept
    {
        return m_action->currentToken();
    }

    /// @copydoc Action::requestStop
    void requestStop() noexcept
    {
        m_action->requestStop();
    }

private:
    std::unique_ptr<Action> m_action;
};

#endif //_CONTENT_PROVIDER_HPP
