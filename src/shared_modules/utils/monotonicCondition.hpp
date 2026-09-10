/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * September 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MONOTONIC_CONDITION_HPP
#define _MONOTONIC_CONDITION_HPP

#include <chrono>
#include <condition_variable>
#include <mutex>

#if defined(__linux__)
#include <ctime>
#include <pthread.h>
#endif

/// Condition variable whose waits are immune to system-clock jumps (see PR description for the libstdc++/glibc
/// rationale).
#if defined(__linux__)

class MonotonicCondition final
{
public:
    MonotonicCondition()
    {
        pthread_condattr_t attr;

        if (pthread_condattr_init(&attr) != 0)
        {
            return;
        }

        if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0)
        {
            m_clock = CLOCK_MONOTONIC;
        }

        pthread_cond_init(&m_cond, &attr);
        pthread_condattr_destroy(&attr);
    }

    ~MonotonicCondition()
    {
        pthread_cond_destroy(&m_cond);
    }

    MonotonicCondition(const MonotonicCondition&) = delete;
    MonotonicCondition& operator=(const MonotonicCondition&) = delete;

    template<typename Predicate>
    bool waitFor(std::unique_lock<std::mutex>& lock, std::chrono::nanoseconds timeout, Predicate predicate)
    {
        const auto deadline {toTimespec(now() + timeout)};

        while (!predicate())
        {
            if (pthread_cond_timedwait(&m_cond, lock.mutex()->native_handle(), &deadline) != 0)
            {
                return predicate();
            }
        }

        return true;
    }

    void notifyAll()
    {
        pthread_cond_broadcast(&m_cond);
    }

    void notifyOne()
    {
        pthread_cond_signal(&m_cond);
    }

    /// The clock this instance's waits are actually bound to; CLOCK_REALTIME
    /// means pthread_condattr_setclock(CLOCK_MONOTONIC) failed and waits fell
    /// back to wall-clock semantics.
    clockid_t clockId() const
    {
        return m_clock;
    }

private:
    std::chrono::nanoseconds now() const
    {
        timespec current {};
        clock_gettime(m_clock, &current);

        return std::chrono::seconds {current.tv_sec} + std::chrono::nanoseconds {current.tv_nsec};
    }

    static timespec toTimespec(std::chrono::nanoseconds point)
    {
        const auto seconds {std::chrono::floor<std::chrono::seconds>(point)};

        return {static_cast<std::time_t>(seconds.count()), static_cast<long>((point - seconds).count())};
    }

    pthread_cond_t m_cond = PTHREAD_COND_INITIALIZER;
    clockid_t m_clock {CLOCK_REALTIME};
};

#else

class MonotonicCondition final
{
public:
    template<typename Predicate>
    bool waitFor(std::unique_lock<std::mutex>& lock, std::chrono::nanoseconds timeout, Predicate predicate)
    {
        return m_cv.wait_for(lock, timeout, predicate);
    }

    void notifyAll()
    {
        m_cv.notify_all();
    }

    void notifyOne()
    {
        m_cv.notify_one();
    }

private:
    std::condition_variable m_cv;
};

#endif

#endif // _MONOTONIC_CONDITION_HPP
