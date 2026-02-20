/**
 * @file request_manager.hpp
 * @brief C++17 replacement for request.c
 *
 * Manages remote request dispatching: receives requests from the
 * manager, queues them in a pool, dispatches to local Unix/Windows
 * sockets or internal handlers, and sends responses back.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_REQUEST_MANAGER_HPP
#define AGENTD_REQUEST_MANAGER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

#include <condition_variable>
#include <mutex>

namespace agentd
{

    /**
     * @brief Manages remote request dispatching.
     *
     * Replaces the C functions: req_init(), req_push(),
     * req_receiver().
     */
    class RequestManager
    {
    public:
        RequestManager() = default;
        ~RequestManager() = default;

        RequestManager(const RequestManager&) = delete;
        RequestManager& operator=(const RequestManager&) = delete;

        /** Initialize request module. */
        void init();

        /** Push a request message into dispatching queue. Return 0 on success or -1 on error. */
        int push(char* buffer, size_t length);

        /** Request receiver thread entry point. */
#ifdef WIN32
        DWORD receiverThread();
#else
        void* receiverThread();
#endif

        /** Access the singleton. */
        static RequestManager& instance();

    private:
        // ── State ────────────────────────────────────────────────────
        OSHash* req_table_ {nullptr};
        req_node_t** req_pool_ {nullptr};
        int pool_i_ {0};
        int pool_j_ {0};

        std::mutex mutex_table_;
        std::mutex mutex_pool_;
        std::condition_variable pool_available_;

        OSHash* allowed_sockets_ {nullptr};
    };

} // namespace agentd

#endif // AGENTD_REQUEST_MANAGER_HPP
