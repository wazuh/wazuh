/**
 * @file message_receiver.hpp
 * @brief C++17 replacement for receiver.c
 *
 * Receives and dispatches messages from the Wazuh manager.
 * Handles decryption, command routing (active-response, syscheck,
 * syscollector, file updates, etc.), and shared-configuration
 * unmerging/reloading.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_MESSAGE_RECEIVER_HPP
#define AGENTD_MESSAGE_RECEIVER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
#ifdef WIN32
#include "execd.h"
#endif
}

#include <cstdio>

namespace agentd
{

    /**
     * @brief Receives and dispatches messages from the manager.
     *
     * Replaces the C functions: receive_msg(), receiver_messages() (WIN32).
     */
    class MessageReceiver
    {
    public:
        MessageReceiver() = default;
        ~MessageReceiver();

        MessageReceiver(const MessageReceiver&) = delete;
        MessageReceiver& operator=(const MessageReceiver&) = delete;

        /**
         * @brief Receive and process one round of messages from the manager.
         * @return 0 on success, -1 if the connection was lost (agent must reconnect).
         */
        int receiveMsg();

#ifdef WIN32
        /**
         * @brief WIN32 message-receiving loop (select + receive_msg).
         * @return 0 (never returns under normal operation).
         */
        int receiverMessages();
#endif

        /** Access the singleton. */
        static MessageReceiver& instance();

    private:
        // ── State corresponding to the original static globals ───────
        FILE* fp_ {nullptr};
        char file_sum_[34] {};
        char file_[OS_SIZE_1024 + 1] {};
        int undefined_msg_logged_ {0};
    };

} // namespace agentd

#endif // AGENTD_MESSAGE_RECEIVER_HPP
