/*
 * Wazuh remoted module - WPK download authorizer backed by the task manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_TASK_MANAGER_WPK_AUTHORIZER_HPP
#define _REMOTED_ENDPOINTS_TASK_MANAGER_WPK_AUTHORIZER_HPP

#include "iWpkAuthorizer.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace remoted::downstream
{
    class AsioUdsHttpClient;
} // namespace remoted::downstream

namespace remoted::endpoints
{
    /**
     * @brief Asks the task manager whether an agent has an open upgrade task for a WPK.
     *
     * One request per decision over the task manager's socket, on a client with its own I/O
     * thread, so `done` runs on that thread. There is no queue: the server's connection ceiling
     * bounds how many requests wait, and each one ends within the connect, write and response
     * deadlines.
     *
     * Only `200 {"task_id": "<non-empty string>"}` grants and only `200 {"task_id": null}` denies;
     * any other outcome is Unavailable, so a misbehaving task manager never serves a file.
     */
    class TaskManagerWpkAuthorizer final : public IWpkAuthorizer
    {
    public:
        TaskManagerWpkAuthorizer(std::string taskSocketPath, uint32_t deadlineMs, uint32_t connectTimeoutMs);
        ~TaskManagerWpkAuthorizer() override;

        TaskManagerWpkAuthorizer(const TaskManagerWpkAuthorizer&) = delete;
        TaskManagerWpkAuthorizer& operator=(const TaskManagerWpkAuthorizer&) = delete;

        void authorize(const std::string& agentId,
                       const std::string& wpkFile,
                       std::function<void(WpkAuthorization)> done) const override;

        /// @brief Join the I/O thread and destroy the client, dropping pending requests (and what their
        /// `done` captured) without calling them. Idempotent; afterwards authorize() answers Unavailable
        /// synchronously. Must not be called from a `done` callback.
        void stop() noexcept;

    private:
        std::string m_taskSocketPath;
        uint32_t m_deadlineMs;
        uint32_t m_connectTimeoutMs;
        // Serializes stop() against an authorize() between its stopped check and sendAsync().
        mutable std::mutex m_mutex;
        bool m_stopped {false};
        std::unique_ptr<remoted::downstream::AsioUdsHttpClient> m_client;
    };
} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_TASK_MANAGER_WPK_AUTHORIZER_HPP
