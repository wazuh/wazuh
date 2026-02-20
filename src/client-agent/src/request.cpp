/**
 * @file request.cpp
 * @brief C++17 implementation of remote request dispatching.
 *
 * Replaces request.c. Encapsulates request management in
 * RequestManager and provides extern "C" trampolines.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "request_manager.hpp"

extern "C"
{
#include "sendmsg.h"
#ifdef WIN32
#include "execd.h"
#include "logcollector.h"
#include "syscheck.h"
#include "wm_agent_upgrade_agent.h"
#endif
}

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pthread.h>

// ── Global variables (declared in agentd.h) ─────────────────────────
extern "C"
{
    int request_pool = 0;
    int rto_sec = 0;
    int rto_msec = 0;
    int max_attempts = 0;
}

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────

    RequestManager& RequestManager::instance()
    {
        static RequestManager inst;
        return inst;
    }

    // ── req_init ─────────────────────────────────────────────────────

    void RequestManager::init()
    {
        int success = 0;
        char* socket_log = nullptr;
        char* socket_sys = nullptr;
        char* socket_wodle = nullptr;
        char* socket_agent = nullptr;

        // Get values from internal options
        request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
        rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
        rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
        max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);

        // Note: The C++ std::mutex/std::condition_variable are already
        // initialized by their constructors.  We still need a pthread
        // mutex/cond pair for the w_mutex_lock / w_cond_wait wrappers
        // that interact with external C code (req_node_t->mutex).
        // For internal pool/table locking we use std::mutex + std::condition_variable.

        // Create hash table and request pool
        if ((req_table_ = OSHash_Create()) == nullptr)
        {
            merror_exit("At req_init(): OSHash_Create()");
        }
        OSHash_SetFreeDataPointer(req_table_, reinterpret_cast<void (*)(void*)>(req_free));

        req_pool_ = static_cast<req_node_t**>(calloc(request_pool, sizeof(req_node_t*)));
        if (!req_pool_)
        {
            merror_exit("At req_init(): calloc()");
        }

        // Create hash table for allowed sockets
        if ((allowed_sockets_ = OSHash_Create()) == nullptr)
        {
            merror("At req_init(): OSHash_Create()");
            goto ret;
        }

        socket_log = strdup(SOCKET_LOGCOLLECTOR);
        socket_sys = strdup(SOCKET_SYSCHECK);
        socket_wodle = strdup(SOCKET_WMODULES);
        socket_agent = strdup(SOCKET_AGENT);

        if (!socket_log || !socket_sys || !socket_wodle || !socket_agent)
        {
            merror("At req_init(): failed to allocate socket strings");
            goto ret;
        }

        if (OSHash_Add(allowed_sockets_, SOCKET_LOGCOLLECTOR, socket_log) != 2 ||
            OSHash_Add(allowed_sockets_, SOCKET_SYSCHECK, socket_sys) != 2 ||
            OSHash_Add(allowed_sockets_, SOCKET_WMODULES, socket_wodle) != 2 ||
            OSHash_Add(allowed_sockets_, SOCKET_AGENT, socket_agent) != 2)
        {
            merror("At req_init(): failed to add socket strings to hash list");
            goto ret;
        }

        success = 1;

    ret:
        if (!success)
        {
            if (req_pool_)
                free(static_cast<void*>(req_pool_));
            if (allowed_sockets_)
                OSHash_Free(allowed_sockets_);
            if (req_table_)
                OSHash_Free(req_table_);
            if (socket_log)
                free(socket_log);
            if (socket_sys)
                free(socket_sys);
            if (socket_wodle)
                free(socket_wodle);
            if (socket_agent)
                free(socket_agent);
            exit(1);
        }
    }

    // ── req_push ─────────────────────────────────────────────────────

    int RequestManager::push(char* buffer, size_t length)
    {
        char* counter {nullptr};
        char* target {nullptr};
        char* payload {nullptr};
        char response[REQ_RESPONSE_LENGTH] {};
        int sock = -1;
        int error {0};
        req_node_t* node {nullptr};

        counter = buffer;

        if ((target = strchr(counter, ' ')) == nullptr)
        {
            merror("Request format is incorrect [target].");
            mdebug2("buffer = \"%s\"", buffer);
            return -1;
        }

        *(target++) = '\0';

        if (IS_ACK(target))
        {
            std::lock_guard<std::mutex> lk(mutex_table_);

            if ((node = static_cast<req_node_t*>(OSHash_Get(req_table_, counter))) != nullptr)
            {
                req_update(node, target, length);
            }
            else
            {
                mdebug1("Request counter (%s) not found. Duplicated ACK?", counter);
            }
        }
        else
        {
            if ((payload = strchr(target, ' ')) == nullptr)
            {
                merror("Request format is incorrect [payload].");
                mdebug2("target = \"%s\"", target);
                return -1;
            }

            *(payload++) = '\0';
            length -= static_cast<size_t>(payload - buffer);

#ifndef WIN32
            if (strcmp(target, "agent") != 0)
            {
                char sockname[PATH_MAX];
                snprintf(sockname, PATH_MAX, "queue/sockets/%s", target);

                if ((sock = OS_ConnectUnixDomain(sockname, SOCK_STREAM, OS_MAXSTR)) < 0)
                {
                    switch (errno)
                    {
                        case ECONNREFUSED:
                            mdebug1("At req_push(): Target '%s' refused connection. The component "
                                    "might be disabled",
                                    target);
                            break;
                        default:
                            mdebug1("At req_push(): Could not connect to socket '%s': %s (%d).",
                                    target,
                                    strerror(errno),
                                    errno);
                    }

                    snprintf(
                        response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s err %s", counter, strerror(errno));
                    send_msg(response, -1);
                    return -1;
                }
            }
#endif

            // Create and insert node
            node = req_create(sock, counter, target, payload, length);
            {
                std::lock_guard<std::mutex> lk(mutex_table_);
                error = OSHash_Add(req_table_, counter, node);
            }

            switch (error)
            {
                case 0:
                    merror("At req_push(): OSHash_Add()");
                    snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s err Internal error", counter);
                    send_msg(response, -1);
                    req_free(node);
                    return -1;

                case 1:
                    mdebug1("Duplicated counter. RTO too short?");
                    req_free(node);
                    return 0;

                case 2:
                {
                    std::lock_guard<std::mutex> lk(mutex_pool_);

                    if (full(pool_i_, pool_j_, request_pool))
                    {
                        merror("Too many requests. Rejecting counter %s.", counter);
                        // unlock pool, then delete from table
                    }
                    else
                    {
                        req_pool_[pool_i_] = node;
                        forward(pool_i_, request_pool);
                        pool_available_.notify_one();
                        break;
                    }
                }

                    // If pool was full, clean up (lock_guard already released)
                    {
                        std::lock_guard<std::mutex> lk(mutex_table_);
                        OSHash_Delete(req_table_, counter);
                    }

                    snprintf(
                        response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s err Too many requests", counter);
                    send_msg(response, -1);
                    req_free(node);
                    return -1;

                default: break;
            }
        }

        return 0;
    }

    // ── req_receiver thread ──────────────────────────────────────────

#ifdef WIN32
    DWORD RequestManager::receiverThread()
#else
    void* RequestManager::receiverThread()
#endif
    {
        ssize_t length = 0;
        req_node_t* node {nullptr};
        char* buffer = nullptr;
        char response[REQ_RESPONSE_LENGTH] {};
        int rlen {0};

        while (true)
        {
            // Get next node from queue
            {
                std::unique_lock<std::mutex> lk(mutex_pool_);

                while (empty(pool_i_, pool_j_))
                {
                    pool_available_.wait(lk);
                }

                node = req_pool_[pool_j_];
                forward(pool_j_, request_pool);
            }

            w_mutex_lock(&node->mutex);

#ifdef WIN32
            // In Windows, forward request to target socket
            if (strncmp(node->target, "agent", 5) == 0)
            {
                length = static_cast<ssize_t>(agcom_dispatch(node->buffer, &buffer));
            }
            else if (strncmp(node->target, "logcollector", 12) == 0)
            {
                length = static_cast<ssize_t>(lccom_dispatch(node->buffer, &buffer));
            }
            else if (strncmp(node->target, "com", 3) == 0)
            {
                length = static_cast<ssize_t>(wcom_dispatch(node->buffer, &buffer));
            }
            else if (strncmp(node->target, "syscheck", 8) == 0)
            {
                length = static_cast<ssize_t>(syscom_dispatch(node->buffer, node->length, &buffer));
            }
            else if (strncmp(node->target, "wmodules", 8) == 0)
            {
                length = static_cast<ssize_t>(wmcom_dispatch(node->buffer, node->length, &buffer));
            }
            else if (strncmp(node->target, "upgrade", 7) == 0)
            {
                length = static_cast<ssize_t>(wm_agent_upgrade_process_command(node->buffer, &buffer));
            }
            else
            {
                os_strdup("err Could not get requested section", buffer);
                length = static_cast<ssize_t>(strlen(buffer));
            }
#else
            // In Unix, forward request to target socket
            if (strncmp(node->target, "agent", 5) == 0)
            {
                length = static_cast<ssize_t>(agcom_dispatch(node->buffer, &buffer));
            }
            else
            {
                buffer = static_cast<char*>(calloc(OS_MAXSTR, sizeof(char)));
                mdebug2("req_receiver(): sending '%s' to socket", node->buffer);

                // Send data
                if (OS_SendSecureTCP(node->sock, node->length, node->buffer) != 0)
                {
                    merror("OS_SendSecureTCP(): %s", strerror(errno));
                    strcpy(buffer, "err Send data");
                    length = static_cast<ssize_t>(strlen(buffer));
                }
                else
                {
                    // Get response
                    length = OS_RecvSecureTCP(node->sock, buffer, OS_MAXSTR);
                    switch (length)
                    {
                        case -1:
                            merror("recv(): %s", strerror(errno));
                            strcpy(buffer, "err Receive data");
                            length = static_cast<ssize_t>(strlen(buffer));
                            break;

                        case 0:
                            mdebug1("Empty message from local client.");
                            strcpy(buffer, "err Empty response");
                            length = static_cast<ssize_t>(strlen(buffer));
                            break;

                        case OS_SOCKTERR:
                            mdebug1("Maximum buffer length reached.");
                            strcpy(buffer, "err Maximum buffer length reached");
                            length = static_cast<ssize_t>(strlen(buffer));
                            break;

                        default: buffer[length] = '\0';
                    }
                }
            }
#endif

            if (length <= 0)
            {
                // Build error string
                strcpy(buffer, "err Disconnected");
                length = static_cast<ssize_t>(strlen(buffer));
            }

            // Build response string
            // Example: #!-req 16 Hello World
            rlen = snprintf(response, REQ_RESPONSE_LENGTH, CONTROL_HEADER HC_REQUEST "%s ", node->counter);
            length += rlen;
            os_realloc(buffer, length + 1, buffer);
            memmove(buffer + rlen, buffer, length - rlen);
            memcpy(buffer, response, rlen);
            buffer[length] = '\0';

            mdebug2("req_receiver(): sending '%s' to server", buffer);

            if (send_msg(buffer, length))
            {
                merror("Sending response to manager.");
            }

            w_mutex_unlock(&node->mutex);

            // Delete node from hash table
            {
                std::lock_guard<std::mutex> lk(mutex_table_);
                OSHash_Delete(req_table_, node->counter);
            }

            // Delete node
            os_free(buffer);
            req_free(node);
        }

#ifdef WIN32
        return 0;
#else
        return nullptr;
#endif
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    void req_init(void)
    {
        agentd::RequestManager::instance().init();
    }

    int req_push(char* buffer, size_t length)
    {
        return agentd::RequestManager::instance().push(buffer, length);
    }

#ifdef WIN32
    DWORD WINAPI req_receiver(__attribute__((unused)) LPVOID arg)
    {
        return agentd::RequestManager::instance().receiverThread();
    }
#else
    void* req_receiver(__attribute__((unused)) void* arg)
    {
        return agentd::RequestManager::instance().receiverThread();
    }
#endif

} // extern "C"
