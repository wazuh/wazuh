/**
 * @file sendmsg.cpp
 * @brief C++17 implementation of the encrypted message sender.
 *
 * Replaces sendmsg.c.  Uses std::mutex instead of pthread_mutex_t.
 * Provides extern "C" trampolines for send_msg() and sender_init().
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "message_sender.hpp"

#include <cerrno>
#include <cstring>

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────────

    MessageSender& MessageSender::instance()
    {
        static MessageSender inst;
        return inst;
    }

    // ── Init ─────────────────────────────────────────────────────────────

    void MessageSender::init()
    {
        // std::mutex is default-constructed and ready to use.
        // This method exists for symmetry with the C API (sender_init).
    }

    // ── Send ─────────────────────────────────────────────────────────────

    int MessageSender::send(const char* msg, ssize_t msg_length)
    {
        char crypt_msg[OS_MAXSTR + 1];

        // Encrypt
        const size_t msg_size =
            CreateSecMSG(&keys, msg, msg_length < 0 ? std::strlen(msg) : static_cast<size_t>(msg_length), crypt_msg, 0);

        if (msg_size == 0)
        {
            merror(SEC_ERROR);
            return -1;
        }

        // Send under lock
        int retval;
        int error = 0;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            retval = OS_SendSecureTCP(agt->sock, static_cast<uint32_t>(msg_size), crypt_msg);
#ifndef WIN32
            error = errno;
#endif
        }

        if (retval == 0)
        {
            w_agentd_state_update(INCREMENT_MSG_SEND, nullptr);
        }
        else
        {
#ifdef WIN32
            error = WSAGetLastError();
            mwarn(SEND_ERROR, "server", win_strerror(error));
#else
            switch (error)
            {
                case EPIPE: mdebug2(TCP_EPIPE); break;
                case ECONNREFUSED: mdebug2(CONN_REF); break;
                default: mwarn(SEND_ERROR, "server", strerror(error)); break;
            }
#endif
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        return retval;
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    void sender_init()
    {
        agentd::MessageSender::instance().init();
    }

    int send_msg(const char* msg, ssize_t msg_length)
    {
        return agentd::MessageSender::instance().send(msg, msg_length);
    }

} // extern "C"
