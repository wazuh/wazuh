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

/**
 * @brief Condition variable whose waits are immune to system-clock jumps.
 *
 * std::condition_variable::wait_for is monotonic only when libstdc++ was built
 * with _GLIBCXX_USE_PTHREAD_COND_CLOCKWAIT (glibc >= 2.30). The agent's
 * toolchain predates it, so its deadlines land on CLOCK_REALTIME and a
 * backward clock jump of N seconds extends every pending wait by N seconds.
 */
#if defined(__linux__)

#include <ctime>
#include <pthread.h>

class MonotonicCondition final
{
public:
    MonotonicCondition()
    {
        pthread_condattr_t attr;
        pthread_condattr_init(&attr);

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

    pthread_cond_t m_cond {};
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

private:
    std::condition_variable m_cv;
};

#endif

#endif // _MONOTONIC_CONDITION_HPP
