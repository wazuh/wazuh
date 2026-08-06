/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "callbackDispatcher.hpp"

CallbackDispatcher::CallbackDispatcher(const hc_callbacks_t& callbacks)
    : m_callbacks(callbacks)
{
}

CallbackDispatcher::~CallbackDispatcher()
{
    stop();
}

void CallbackDispatcher::start()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_running)
    {
        return;
    }

    m_running = true;
    m_draining = false;
    m_worker = std::thread(&CallbackDispatcher::run, this);
}

void CallbackDispatcher::stop()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_running)
        {
            return;
        }

        m_draining = true; // Run the remaining queue, then exit.
    }
    m_cv.notify_all();

    if (m_worker.joinable())
    {
        m_worker.join();
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_running = false;
}

void CallbackDispatcher::enqueue(std::function<void()> task)
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        if (!m_running || m_draining)
        {
            return; // Reject once stopping: no callback may outlive stop().
        }

        m_queue.push(std::move(task));
    }
    m_cv.notify_one();
}

void CallbackDispatcher::run()
{
    while (true)
    {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return !m_queue.empty() || m_draining; });

            if (m_queue.empty())
            {
                return; // Draining and nothing left.
            }

            task = std::move(m_queue.front());
            m_queue.pop();
        }
        task(); // Outside the lock: handlers may be slow but never block peers.
    }
}

void CallbackDispatcher::onStartupResult(bool accepted, const std::string& handshakeJson)
{
    if (m_callbacks.on_startup_result == nullptr)
    {
        return;
    }

    enqueue([this, accepted, handshakeJson]
    { m_callbacks.on_startup_result(accepted, handshakeJson.c_str(), m_callbacks.user_data); });
}

void CallbackDispatcher::onTask(const std::string& taskId, const std::string& taskType,
                                const std::string& payloadJson)
{
    if (m_callbacks.on_task == nullptr)
    {
        return;
    }

    enqueue([this, taskId, taskType, payloadJson]
    {
        m_callbacks.on_task(taskId.c_str(), taskType.c_str(), payloadJson.c_str(),
                            m_callbacks.user_data);
    });
}

void CallbackDispatcher::onReenrollRequired()
{
    if (m_callbacks.on_reenroll_required == nullptr)
    {
        return;
    }

    enqueue([this] { m_callbacks.on_reenroll_required(m_callbacks.user_data); });
}

void CallbackDispatcher::onConfigDownloaded(const std::string& configHash,
                                            std::shared_ptr<SpoolFile> file)
{
    if (m_callbacks.on_config_downloaded == nullptr)
    {
        return; // Last reference dropped here: the temp file is deleted now.
    }

    // The lambda owns the file; run() destroys the task right after invoking
    // it, so the file is deleted as soon as the C callback returns.
    enqueue([this, configHash, file = std::move(file)]
    {
        m_callbacks.on_config_downloaded(configHash.c_str(), file->path().c_str(),
                                         m_callbacks.user_data);
    });
}

void CallbackDispatcher::onUpgradeReady(const std::string& taskId, const std::string& wpkFile,
                                        std::shared_ptr<SpoolFile> file, const std::string& installer)
{
    if (m_callbacks.on_remote_upgrade_ready == nullptr)
    {
        return; // Last reference dropped here: the temp WPK file is deleted now.
    }

    // The lambda owns the file; run() destroys the task right after invoking
    // it, so the file is deleted as soon as the C callback returns (same
    // convention as onConfigDownloaded).
    enqueue([this, taskId, wpkFile, file = std::move(file), installer]
    {
        m_callbacks.on_remote_upgrade_ready(taskId.c_str(), wpkFile.c_str(), file->path().c_str(),
                                            installer.c_str(), m_callbacks.user_data);
    });
}

void CallbackDispatcher::onTaskFailed(const std::string& taskId, const std::string& taskType,
                                      const std::string& reason)
{
    if (m_callbacks.on_task_failed == nullptr)
    {
        return; // Optional callback: this failure category simply goes uncounted.
    }

    enqueue([this, taskId, taskType, reason]
    {
        m_callbacks.on_task_failed(taskId.c_str(), taskType.c_str(), reason.c_str(),
                                   m_callbacks.user_data);
    });
}

void CallbackDispatcher::onManagerConfigHash(const std::string& configHash)
{
    if (m_callbacks.on_manager_config_hash == nullptr)
    {
        return;
    }

    enqueue([this, configHash]
    {
        m_callbacks.on_manager_config_hash(configHash.c_str(), m_callbacks.user_data);
    });
}

void CallbackDispatcher::onAgentGroups(const std::string& groupsCsv)
{
    if (m_callbacks.on_agent_groups == nullptr)
    {
        return;
    }

    enqueue([this, groupsCsv]
    {
        m_callbacks.on_agent_groups(groupsCsv.c_str(), m_callbacks.user_data);
    });
}

void CallbackDispatcher::onSyncResponse(const std::string& sessionId, int result,
                                        const std::string& body)
{
    if (m_callbacks.on_sync_response == nullptr)
    {
        return;
    }

    enqueue([this, sessionId, result, body]
    {
        // Length-carrying: the body is the manager's raw /stateful JSON response, and
        // c_str() alone would truncate it at the first embedded NUL, if any.
        m_callbacks.on_sync_response(
            sessionId.c_str(), result, body.data(), body.size(), m_callbacks.user_data);
    });
}

void CallbackDispatcher::onStateChange(hc_conn_state_t state)
{
    if (m_callbacks.on_state_change == nullptr)
    {
        return;
    }

    enqueue([this, state] { m_callbacks.on_state_change(state, m_callbacks.user_data); });
}

void CallbackDispatcher::onBufferLevel(hc_buffer_level_t level)
{
    if (m_callbacks.on_buffer_level == nullptr)
    {
        return;
    }

    enqueue([this, level] { m_callbacks.on_buffer_level(level, m_callbacks.user_data); });
}

void CallbackDispatcher::onProducerPause(bool paused)
{
    if (m_callbacks.on_producer_pause == nullptr)
    {
        return;
    }

    enqueue([this, paused] { m_callbacks.on_producer_pause(paused, m_callbacks.user_data); });
}
