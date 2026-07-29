/* Copyright (C) 2015, Wazuh Inc.
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
#include <memory>

extern volatile bool event_received;
extern volatile bool ebpf_hc_created;

/*
 * Mockable seam over the eBPF Module engine's API (#37396 cutover). Tests
 * substitute rt_engine_api's members the same way the old w_bpf_helpers_t
 * dispatch table let them substitute individual libbpf calls — except now
 * there are only three functions to mock, matching the engine's actual
 * consumer-facing surface, instead of a dozen internal libbpf entry points.
 */
struct rt_engine_api_t
{
    rt_handle_t (*open)(const struct rt_filter*) = rt_open;
    int (*poll)(rt_handle_t, rt_sink_fn, void*, int) = rt_poll;
    void (*close)(rt_handle_t) = rt_close;
};

extern rt_engine_api_t rt_engine_api;

class fimebpf
{
    public:
        static fimebpf& instance()
        {
            static fimebpf s_instance;
            return s_instance;
        }

        // Function pointer types for required C functions
        using fim_configuration_directory_t = directory_t* (*)(const char*, bool);
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

#endif // EBPF_WHODATA_HPP
