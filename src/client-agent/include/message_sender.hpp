/**
 * @file message_sender.hpp
 * @brief C++17 replacement for sendmsg.h / sendmsg.c
 *
 * Thread-safe wrapper around the Wazuh encrypted-send path:
 * CreateSecMSG() -> OS_SendSecureTCP().
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_MESSAGE_SENDER_HPP
#define AGENTD_MESSAGE_SENDER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h" // agt, keys
#include "state.h"  // w_agentd_state_update, INCREMENT_MSG_SEND
}

#include <cstring>

namespace agentd
{

    /**
     * @brief Thread-safe encrypted message sender.
     *
     * Replaces the C `send_msg()` + `sender_init()` pair.
     * Encrypts the payload via CreateSecMSG(), then sends over
     * the agent's TCP socket, all under a mutex.
     */
    class MessageSender
    {
    public:
        MessageSender() = default;
        ~MessageSender() = default;

        // Non-copyable (owns a mutex)
        MessageSender(const MessageSender&) = delete;
        MessageSender& operator=(const MessageSender&) = delete;

        /** Initialise (nothing heavy — just prepares the mutex). */
        void init();

        /**
         * Encrypt and send a message to the connected manager.
         *
         * @param msg       Payload to send.
         * @param msg_length  Length of @p msg, or -1 to auto-detect via strlen.
         * @return 0 on success, non-zero on failure.
         */
        int send(const char* msg, ssize_t msg_length);

        /** Access the singleton instance. */
        static MessageSender& instance();

    private:
        std::mutex mutex_;
    };

} // namespace agentd

#endif // AGENTD_MESSAGE_SENDER_HPP
