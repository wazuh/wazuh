/**
 * @file event_forwarder.hpp
 * @brief C++17 replacement for event-forward.c
 *
 * Receives messages from the local Unix domain socket queue and
 * either buffers them (anti-flooding) or sends them directly to
 * the manager.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_EVENT_FORWARDER_HPP
#define AGENTD_EVENT_FORWARDER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Drains the local message queue and forwards events.
     *
     * Replaces the C EventForward() function.  Reads from agt->m_queue
     * and either pushes into the anti-flooding buffer or sends directly
     * to the manager, depending on the buffer configuration.
     */
    class EventForwarder
    {
    public:
        EventForwarder() = default;
        ~EventForwarder() = default;

        EventForwarder(const EventForwarder&) = delete;
        EventForwarder& operator=(const EventForwarder&) = delete;

        /**
         * Drain the local queue once (non-blocking recv loop).
         * Designed to be called from the main select() loop.
         */
        void forwardEvents();

        /** Access the singleton. */
        static EventForwarder& instance();
    };

} // namespace agentd

#endif // AGENTD_EVENT_FORWARDER_HPP
