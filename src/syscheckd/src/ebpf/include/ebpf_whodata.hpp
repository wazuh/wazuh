/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef EBPF_WHODATA_HPP
#define EBPF_WHODATA_HPP

#include "ebpf_whodata.h"
#include "rt_engine.h"
#include <bounded_queue.hpp>
#include <memory>
#include <string>

// Defined in src/ebpf_whodata.cpp
extern volatile bool event_received;
extern volatile bool ebpf_hc_created;

struct rt_engine_api_t
{
    rt_handle_t (*open)(const struct rt_filter*) = rt_open;
    int (*poll)(rt_handle_t, rt_sink_fn, void*, int) = rt_poll;
    void (*close)(rt_handle_t) = rt_close;
};
extern rt_engine_api_t rt_engine_api;

struct healthcheck_context
{
    const char* path;
    unsigned int event_type;
};

class fimebpf
{
    public:
        static fimebpf& instance()
        {
            static fimebpf s_instance;
            return s_instance;
        }

        // Function pointer types for required C functions
        using fim_configuration_directory_t = bool (*)(const char*);
        using get_user_t = char* (*)(int);
        using get_group_t = char* (*)(int);
        using fim_whodata_event_t = void (*)(whodata_evt*);
        using free_whodata_event_t = void (*)(whodata_evt*);
        using loggingFunction_t = void (*)(modules_log_level_t, const char*);
        using abspath_t = char* (*)(const char*, char*, size_t);
        using fimShutdownProcessOn_t = bool (*)();

        // Initialize the class with pointers to the C functions
        void initialize(fim_configuration_directory_t fim_conf,
                        get_user_t get_user,
                        get_group_t get_group,
                        fim_whodata_event_t fim_whodata_event,
                        free_whodata_event_t free_whodata_event,
                        loggingFunction_t loggingFunction,
                        abspath_t abspath,
                        fimShutdownProcessOn_t fimShutdownProcessOn,
                        unsigned int syscheckQueueSize)
        {
            m_fim_configuration_directory = fim_conf;
            m_get_user = get_user;
            m_get_group = get_group;
            m_fim_whodata_event = fim_whodata_event;
            m_free_whodata_event = free_whodata_event;
            m_loggingFunction = loggingFunction;
            m_abspath = abspath;
            m_queue_size = syscheckQueueSize;
            m_fim_shutdown_process_on = fimShutdownProcessOn;
        }

    protected:
        fimebpf() = default;
        ~fimebpf() = default;
        fimebpf(const fimebpf&) = delete;
        fimebpf& operator=(const fimebpf&) = delete;

    public:
        fim_configuration_directory_t m_fim_configuration_directory = nullptr;
        get_user_t m_get_user = nullptr;
        get_group_t m_get_group = nullptr;
        fim_whodata_event_t m_fim_whodata_event = nullptr;
        free_whodata_event_t m_free_whodata_event = nullptr;
        loggingFunction_t m_loggingFunction = nullptr;
        abspath_t m_abspath = nullptr;
        unsigned int m_queue_size;
        fimShutdownProcessOn_t m_fim_shutdown_process_on;
};

struct dynamic_file_event
{
    std::string filename;
    std::string cwd;
    std::string parent_cwd;
    std::string comm;
    std::string parent_comm;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t euid;
    uint32_t login_uid;
    uint64_t inode;
    uint64_t dev;
};

void handle_event(const struct rt_file_event* event, void* ctx);
void ebpf_pop_events(fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& queue);

#endif // EBPF_WHODATA_HPP
