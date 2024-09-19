/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONDITION_SYNC_HPP
#define _CONDITION_SYNC_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

/**
 * @brief Synchronization class based on a condition variable.
 *
 * Simple synchronization mechanism for coordinating threads based on a boolean condition.
 */
class ConditionSync
{
public:
    /**
     * @brief Construct a new Condition Sync object
     *
     * @param initialState The initial value of the condition.
     */
    explicit ConditionSync(bool initialState)
        : m_condition(initialState) {};

    /**
     * @brief Waits for the condition to become true or until a timeout occurs.
     *
     * @param timeout Maximum duration to wait for the condition.
     * @return True if the condition becomes true, false if a timeout occurs.
     */
    bool waitFor(std::chrono::milliseconds timeout)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_cv.wait_for(lock, timeout, [this] { return m_condition.load(); });
    }

    /**
     * @brief Checks the current value of the condition.
     * @return The current value of the condition.
     */
    bool check()
    {
        return m_condition.load();
    }

    /**
     * @brief Sets the value of the condition to the specified value and notifies the waiting threads.
     * @param value The new value of the condition.
     *
     */
    void set(bool value)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_condition = value;
        m_cv.notify_all();
    }

private:
    std::atomic<bool> m_condition; ///< The shared boolean condition.
    std::mutex m_mutex;            ///< Mutex for synchronization.
    std::condition_variable m_cv;  ///< Condition variable for signaling.
};

#endif // _CONDITION_SYNC_HPP
