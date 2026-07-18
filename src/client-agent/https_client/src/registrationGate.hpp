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

#ifndef _HC_REGISTRATION_GATE_HPP
#define _HC_REGISTRATION_GATE_HPP

#include <condition_variable>
#include <mutex>

/**
 * @brief One-time gate that holds the data streams until Startup is accepted
 *        (D6: producers wait until the handshake succeeds once). abort() wakes
 *        any waiter during shutdown so a client that never registered still
 *        stops cleanly.
 */
class RegistrationGate final
{
    public:
        void open()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_open = true;
            }
            m_cv.notify_all();
        }

        void abort()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_aborted = true;
            }
            m_cv.notify_all();
        }

        /// Blocks until opened or aborted. Returns true if opened (proceed), false
        /// if aborted before registration (exit).
        bool wait()
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return m_open || m_aborted; });
            return m_open && !m_aborted;
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_open {false};
        bool m_aborted {false};
};

#endif // _HC_REGISTRATION_GATE_HPP
