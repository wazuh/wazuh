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

/**
 * @brief Condition variable whose timeouts are immune to system-clock jumps.
 *
 * std::condition_variable::wait_for is only monotonic when libstdc++ was built
 * with _GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT (glibc >= 2.30); the agent's build
 * toolchain predates that, so its waits are anchored to CLOCK_REALTIME and a
 * backward clock jump of N seconds extends every pending wait by N seconds.
 * This wrapper pins the condition variable to CLOCK_MONOTONIC instead, with
 * the same graceful fallback used by os_auth/src/auth.c. Platforms without
 * pthread_condattr_setclock keep the standard implementation.
 */
#if defined(__linux__)

class MonotonicCondition final
{
public:
    class Mutex final
    {
    public:
        Mutex()
        {
            pthread_mutex_init(&m_mutex, nullptr);
        }

        ~Mutex()
        {
            pthread_mutex_destroy(&m_mutex);
        }

        Mutex(const Mutex&) = delete;
        Mutex& operator=(const Mutex&) = delete;

        void lock()
        {
            pthread_mutex_lock(&m_mutex);
        }

        void unlock()
        {
            pthread_mutex_unlock(&m_mutex);
        }

        pthread_mutex_t* native() noexcept
        {
            return &m_mutex;
        }

    private:
        pthread_mutex_t m_mutex {};
    };

    MonotonicCondition()
    {
        pthread_condattr_t attr;

        if (pthread_condattr_init(&attr) != 0)
        {
            pthread_cond_init(&m_cond, nullptr);
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
    bool waitFor(std::unique_lock<Mutex>& lock, std::chrono::milliseconds timeout, Predicate predicate)
    {
        if (predicate())
        {
            return true;
        }

        if (timeout <= std::chrono::milliseconds::zero())
        {
            return false;
        }

        const auto deadline {deadlineFrom(timeout)};

        while (pthread_cond_timedwait(&m_cond, lock.mutex()->native(), &deadline) == 0)
        {
            if (predicate())
            {
                return true;
            }
        }

        return predicate();
    }

    void notifyAll()
    {
        pthread_cond_broadcast(&m_cond);
    }

private:
    timespec deadlineFrom(std::chrono::milliseconds timeout) const
    {
        timespec deadline {};
        clock_gettime(m_clock, &deadline);

        const auto seconds {std::chrono::duration_cast<std::chrono::seconds>(timeout)};
        const auto nanoseconds {deadline.tv_nsec +
                                std::chrono::duration_cast<std::chrono::nanoseconds>(timeout - seconds).count()};

        deadline.tv_sec += static_cast<time_t>(seconds.count() + nanoseconds / 1000000000);
        deadline.tv_nsec = static_cast<long>(nanoseconds % 1000000000);

        return deadline;
    }

    pthread_cond_t m_cond {};
    clockid_t m_clock {CLOCK_REALTIME};
};

#else

class MonotonicCondition final
{
public:
    using Mutex = std::mutex;

    template<typename Predicate>
    bool waitFor(std::unique_lock<Mutex>& lock, std::chrono::milliseconds timeout, Predicate predicate)
    {
        return m_cv.wait_for(lock, timeout, predicate);
    }

    void notifyAll()
    {
        m_cv.notify_all();
    }

private:
    std::condition_variable m_cv;
};

#endif

#endif // _MONOTONIC_CONDITION_HPP
