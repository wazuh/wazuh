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

#ifndef _HC_STOP_TOKEN_HPP
#define _HC_STOP_TOKEN_HPP

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

/**
 * @brief Interruptible wait bound to a cooperative stop flag.
 *
 * One Waiter per stream thread: the loop sleeps in waitFor() and is woken
 * either by notify() (forced flush / notify_now, keep running) or by
 * requestStop() (shutdown). The underlying atomic is exposed so in-flight
 * HTTP transfers can be aborted through the performer's abort wiring.
 *
 * waitFor()/notify() are virtual so tests can script delays deterministically
 * (FakeWaiter) without real sleeps.
 */
class Waiter
{
    public:
        virtual ~Waiter() = default;

        /// Sleeps up to timeout. Returns false when stop was requested (the loop
        /// must exit); true when the wait elapsed or notify() woke it early.
        virtual bool waitFor(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait_for(lock, timeout, [this] { return m_stop.load() || m_wake; });
            m_wake = false;
            return !m_stop.load();
        }

        /// Wakes a pending waitFor() without stopping (e.g. hc_notify_now).
        virtual void notify()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_wake = true;
            }
            m_cv.notify_all();
        }

        /// Requests cooperative stop and wakes any pending waitFor().
        void requestStop()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_stop = true;
            }
            m_cv.notify_all();
        }

        bool stopRequested() const
        {
            return m_stop.load();
        }

        /// The abort flag wired into in-flight transfers (CURLOPT_XFERINFO path).
        const std::atomic<bool>* stopFlag() const
        {
            return &m_stop;
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stop {false};
        bool m_wake {false};
};

#endif // _HC_STOP_TOKEN_HPP
