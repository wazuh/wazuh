/**
 * @file receiver.cpp
 * @brief C++17 implementation of message reception from the manager.
 *
 * Replaces receiver.c. Encapsulates message reception and dispatching
 * logic in MessageReceiver and provides extern "C" trampolines.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "message_receiver.hpp"

extern "C"
{
#include "sendmsg.h"
#include "state.h"

#include "md5_op.h"
#include "syscheck_op.h"
#include "wmodules.h"
}

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <thread>

#ifdef WIN32
extern "C"
{
    extern w_queue_t* winexec_queue;
}
#endif

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────────

    MessageReceiver& MessageReceiver::instance()
    {
        static MessageReceiver inst;
        return inst;
    }

    // ── Destructor ───────────────────────────────────────────────────────

    MessageReceiver::~MessageReceiver()
    {
        if (fp_)
        {
            fclose(fp_);
            fp_ = nullptr;
        }
    }

    // ── receive_msg ──────────────────────────────────────────────────────

    int MessageReceiver::receiveMsg()
    {
        ssize_t recv_b {0};
        size_t msg_length {0};
        int reads = 0;
        char buffer[OS_MAXSTR + 1] {};
        char cleartext[OS_MAXSTR + 1] {};
        char* tmp_msg {nullptr};

        /* Read until no more messages are available */
        while (true)
        {
            /* Only one read per call */
            if (reads++)
            {
                break;
            }

            recv_b = OS_RecvSecureTCP(agt->sock, buffer, OS_MAXSTR);

            // Manager disconnected or error
            if (recv_b <= 0)
            {
                switch (recv_b)
                {
                    case OS_SOCKTERR: merror("Corrupt payload (exceeding size) received."); break;

                    case -1:
#ifndef WIN32
                        if (errno == ENOTCONN)
                        {
                            mdebug1("Manager disconnected (ENOTCONN).");
                        }
                        else
                        {
                            merror("Connection socket: %s (%d)", strerror(errno), errno);
                        }
#else
                        merror("Connection socket: %s (%d)", win_strerror(WSAGetLastError()), WSAGetLastError());
#endif
                        break;

                    case 0: mdebug1("Manager disconnected."); break;

                    default: break;
                }

                // -1 means that the agent must reconnect
                return -1;
            }

            buffer[recv_b] = '\0';

            if (ReadSecMSG(
                    &keys, buffer, cleartext, 0, recv_b - 1, &msg_length, agt->server[agt->rip_id].rip, &tmp_msg) !=
                    KS_VALID ||
                tmp_msg == nullptr)
            {
                mwarn(MSG_ERROR, agt->server[agt->rip_id].rip);
                continue;
            }

            mdebug2("Received message: '%s'", tmp_msg);

            /* Check for commands */
            if (IsValidHeader(tmp_msg))
            {
                undefined_msg_logged_ = 0;

                available_server = time(nullptr);
                w_agentd_state_update(UPDATE_ACK, static_cast<void*>(&available_server));

                /* If it is an active response message */
                if (strncmp(tmp_msg, EXECD_HEADER, strlen(EXECD_HEADER)) == 0)
                {
                    tmp_msg += strlen(EXECD_HEADER);
#ifndef WIN32
                    if (agt->execdq >= 0)
                    {
                        if (OS_SendUnix(agt->execdq, tmp_msg, 0) < 0)
                        {
                            mdebug1("Error communicating with execd");
                        }
                    }
#else
                    if (agt->execdq >= 0)
                    {
                        queue_push_ex(winexec_queue, strdup(tmp_msg));
                    }
#endif
                    continue;
                }

                /* Force reconnect agent to the manager */
                else if (strncmp(tmp_msg, HC_FORCE_RECONNECT, strlen(HC_FORCE_RECONNECT)) == 0)
                {
                    /* Set lock and wait for it */
                    minfo("Wazuh Agent will be reconnected because a reconnect message was received");
                    os_setwait();
                    w_agentd_state_update(UPDATE_STATUS,
                                          reinterpret_cast<void*>(static_cast<intptr_t>(GA_STATUS_NACTIVE)));

                    /* Send sync message */
                    start_agent(0);

                    os_delwait();
                    w_agentd_state_update(UPDATE_STATUS,
                                          reinterpret_cast<void*>(static_cast<intptr_t>(GA_STATUS_ACTIVE)));
                    continue;
                }

                /* Syscheck */
                else if (strncmp(tmp_msg, HC_SK, strlen(HC_SK)) == 0 ||
                         strncmp(tmp_msg, FIM_SYNC_HEADER, strlen(FIM_SYNC_HEADER)) == 0)
                {
                    ag_send_syscheck(tmp_msg, msg_length);
                    continue;
                }

                /* Syscollector */
                else if (strncmp(tmp_msg, HC_SYSCOLLECTOR, strlen(HC_SYSCOLLECTOR)) == 0 ||
                         strncmp(tmp_msg, SYSCOLECTOR_SYNC_HEADER, strlen(SYSCOLECTOR_SYNC_HEADER)) == 0 ||
                         strncmp(tmp_msg, SCA_SYNC_HEADER, strlen(SCA_SYNC_HEADER)) == 0 ||
                         strncmp(tmp_msg, AGENT_INFO_SYNC_HEADER, strlen(AGENT_INFO_SYNC_HEADER)) == 0)
                {
                    wmcom_send(tmp_msg, msg_length);
                    continue;
                }

                /* Ack from server */
                else if (strcmp(tmp_msg, HC_ACK) == 0)
                {
                    continue;
                }

                // Request from manager (or request ack)
                else if (IS_REQ(tmp_msg))
                {
                    req_push(tmp_msg + strlen(HC_REQUEST), msg_length - strlen(HC_REQUEST) - 3);
                    continue;
                }

                /* Security configuration assessment DB request */
                else if (strncmp(tmp_msg, CFGA_DB_DUMP, strlen(CFGA_DB_DUMP)) == 0)
                {
                    mwarn("SCA dump operation is deprecated");
                    continue;
                }

                /* Close any open file pointer if it was being written to */
                if (fp_)
                {
                    fclose(fp_);
                    fp_ = nullptr;
                }

                /* File update message */
                if (strncmp(tmp_msg, FILE_UPDATE_HEADER, strlen(FILE_UPDATE_HEADER)) == 0)
                {
                    char* validate_file;

                    tmp_msg += strlen(FILE_UPDATE_HEADER);

                    /* Going to after the file sum */
                    validate_file = strchr(tmp_msg, ' ');
                    if (!validate_file)
                    {
                        continue;
                    }

                    if (w_ref_parent_folder(validate_file))
                    {
                        mwarn("Invalid file '%s', vulnerable to directory traversal attack. Ignoring.", validate_file);
                        continue;
                    }

                    *validate_file = '\0';

                    /* Copy the file sum */
                    strncpy(file_sum_, tmp_msg, 33);

                    /* Set tmp_msg to the beginning of the file name */
                    validate_file++;
                    tmp_msg = validate_file;

                    if ((validate_file = strchr(tmp_msg, '\n')) != nullptr)
                    {
                        *validate_file = '\0';
                    }

                    while ((validate_file = strchr(tmp_msg, '/')) != nullptr)
                    {
                        *validate_file = '-';
                    }

                    if (tmp_msg[0] == '.')
                    {
                        tmp_msg[0] = '-';
                    }

                    snprintf(file_, OS_SIZE_1024, "%s/%s", SHAREDCFG_DIR, tmp_msg);

                    fp_ = wfopen(file_, "w");
                    if (!fp_)
                    {
                        merror(FOPEN_ERROR, file_, errno, strerror(errno));
                    }
                }

                else if (strncmp(tmp_msg, FILE_CLOSE_HEADER, strlen(FILE_CLOSE_HEADER)) == 0)
                {
                    /* No error */
                    os_md5 currently_md5 {};

                    if (file_[0] == '\0')
                    {
                        /* Nothing to be done */
                    }
                    else if (OS_MD5_File(file_, currently_md5, OS_TEXT) < 0)
                    {
                        /* Remove file */
                        unlink(file_);
                        file_[0] = '\0';
                    }
                    else
                    {
                        if (strcmp(currently_md5, file_sum_) != 0)
                        {
                            mdebug1("Failed md5 for: %s -- deleting.", file_);
                            unlink(file_);
                        }
                        else
                        {
                            char* final_file;

                            /* Rename the file to its original name */
                            final_file = strrchr(file_, '/');
                            if (final_file)
                            {
                                if (strcmp(final_file + 1, SHAREDCFG_FILENAME) == 0)
                                {
                                    char** ignore_list;
                                    os_calloc(2, sizeof(char*), ignore_list);
                                    os_strdup(SHAREDCFG_FILENAME, *ignore_list);
                                    if (!UnmergeFiles(file_, SHAREDCFG_DIR, OS_TEXT, &ignore_list))
                                    {
                                        char msg_output[OS_MAXSTR];

                                        snprintf(msg_output,
                                                 OS_MAXSTR,
                                                 "%c:%s:%s",
                                                 LOCALFILE_MQ,
                                                 "wazuh-agent",
                                                 AG_IN_UNMERGE);
                                        send_msg(msg_output, -1);
                                    }
                                    else
                                    {
                                        if (cldir_ex_ignore(SHAREDCFG_DIR, const_cast<const char**>(ignore_list)))
                                        {
                                            mwarn("Could not clean up shared directory.");
                                        }
                                        clear_merged_hash_cache();
                                        if (agt->flags.remote_conf && !verifyRemoteConf())
                                        {
                                            if (agt->flags.auto_restart)
                                            {
                                                minfo("Agent is reloading due to shared configuration "
                                                      "changes.");
                                                reloadAgent();
                                            }
                                            else
                                            {
                                                minfo("Shared agent configuration has been updated.");
                                            }
                                        }
                                    }
                                    free_strarray(ignore_list);
                                }
                            }
                            else
                            {
                                /* Remove file */
                                unlink(file_);
                            }
                        }

                        file_[0] = '\0';
                    }
                }

                else
                {
                    mwarn("Unknown message received from server.");
                }
            }

            else if (fp_)
            {
                available_server = time(nullptr);
                w_agentd_state_update(UPDATE_ACK, static_cast<void*>(&available_server));
                fprintf(fp_, "%s", tmp_msg);
            }

            else if (!undefined_msg_logged_)
            {
                mwarn("Unknown message received. No action defined.");
                undefined_msg_logged_ = 1;
            }
        }

        return 0;
    }

#ifdef WIN32
    // ── receiver_messages (WIN32 only) ───────────────────────────────────

    int MessageReceiver::receiverMessages()
    {
        int rc = 0;

        fd_set fdset;
        struct timeval selecttime {};

        while (true)
        {
            /* Run timeout commands */
            if (agt->execdq >= 0)
            {
                ExecdTimeoutRun();
            }

            /* sock must be set */
            if (agt->sock == -1)
            {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            run_notify();

            FD_ZERO(&fdset);
            FD_SET(agt->sock, &fdset);

            /* Wait for 1 second */
            selecttime.tv_sec = 1;
            selecttime.tv_usec = 0;

            /* Wait with a timeout for any descriptor */
            rc = select(agt->sock + 1, &fdset, nullptr, nullptr, &selecttime);
            if (rc == -1)
            {
                merror(SELECT_ERROR, WSAGetLastError(), win_strerror(WSAGetLastError()));
                std::this_thread::sleep_for(std::chrono::seconds(30));
                continue;
            }
            else if (rc == 0)
            {
                continue;
            }

            if (receiveMsg() < 0)
            {
                w_agentd_state_update(UPDATE_STATUS, reinterpret_cast<void*>(static_cast<intptr_t>(GA_STATUS_NACTIVE)));
                merror(LOST_ERROR);
                os_setwait();
                start_agent(0);
                minfo(SERVER_UP);
                os_delwait();
                w_agentd_state_update(UPDATE_STATUS, reinterpret_cast<void*>(static_cast<intptr_t>(GA_STATUS_ACTIVE)));
            }
        }

        return 0;
    }
#endif

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

#ifdef WIN32
extern "C"
{
    /* WIN32 global used by receiver — defined here, declared extern elsewhere */
    w_queue_t* winexec_queue = nullptr;
}
#endif

extern "C"
{

    int receive_msg(void)
    {
        return agentd::MessageReceiver::instance().receiveMsg();
    }

#ifdef WIN32
    int receiver_messages(void)
    {
        return agentd::MessageReceiver::instance().receiverMessages();
    }
#endif

} // extern "C"
