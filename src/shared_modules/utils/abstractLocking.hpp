/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ABSTRACT_LOCKING_HPP
#define _ABSTRACT_LOCKING_HPP

#include <mutex>
#include <shared_mutex>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    class ILocking
    {
        public:
            virtual ~ILocking() = default;
            virtual void lock() = 0;
            virtual void unlock() = 0;
    };

    class SharedLocking final : public ILocking
    {
            std::shared_lock<std::shared_timed_mutex> m_lock;
        public:
            explicit SharedLocking(std::shared_timed_mutex& mutex)
                : m_lock(std::shared_lock<std::shared_timed_mutex>(mutex)) {};

            virtual ~SharedLocking() = default;
            virtual void lock() override
            {
                m_lock.lock();
            }
            virtual void unlock() override
            {
                m_lock.unlock();
            }
    };

    class ExclusiveLocking final : public ILocking
    {
            std::unique_lock<std::shared_timed_mutex> m_lock;
        public:
            explicit ExclusiveLocking(std::shared_timed_mutex& mutex)
                : m_lock(std::unique_lock<std::shared_timed_mutex>(mutex)) {};

            virtual ~ExclusiveLocking() = default;
            virtual void lock() override
            {
                m_lock.lock();
            }
            virtual void unlock() override
            {
                m_lock.unlock();
            }
    };
};

#endif /* _ABSTRACT_LOCKING_HPP */
