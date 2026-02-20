/**
 * @file event-forward.cpp
 * @brief C++17 implementation of event forwarding.
 *
 * Replaces event-forward.c.  Drains the local queue and either
 * buffers or directly sends messages to the manager.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "event_forwarder.hpp"

extern "C"
{
#include "sendmsg.h"
#include "state.h"
}

#include <sys/socket.h>
#include <sys/types.h>

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────────

    EventForwarder& EventForwarder::instance()
    {
        static EventForwarder inst;
        return inst;
    }

    // ── Forward ──────────────────────────────────────────────────────────

    void EventForwarder::forwardEvents()
    {
        ssize_t recv_b;
        char msg[OS_MAXSTR + 1];

        msg[0] = '\0';
        msg[OS_MAXSTR] = '\0';

        while ((recv_b = recv(agt->m_queue, msg, OS_MAXSTR, MSG_DONTWAIT)) > 0)
        {
            if (agt->buffer)
            {
                if (msg[0] == 's')
                {
                    if (buffer_append(msg, recv_b) < 0)
                    {
                        break;
                    }
                }
                else
                {
                    msg[recv_b] = '\0';
                    if (buffer_append(msg, -1) < 0)
                    {
                        break;
                    }
                }
            }
            else
            {
                w_agentd_state_update(INCREMENT_MSG_COUNT, nullptr);

                if (msg[0] == 's')
                {
                    if (send_msg(msg, recv_b) < 0)
                        break;
                }
                else
                {
                    msg[recv_b] = '\0';
                    if (send_msg(msg, -1) < 0)
                        break;
                }
            }
        }
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampoline
// =====================================================================

extern "C"
{

    void* EventForward(void)
    {
        agentd::EventForwarder::instance().forwardEvents();
        return nullptr;
    }

} // extern "C"
