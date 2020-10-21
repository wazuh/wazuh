/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_IMP_H
#define _SYSCOLLECTOR_IMP_H
#include <chrono>
#include <thread>
#include <atomic>
#include "sysInfo.hpp"
#include "json.hpp"

class Syscollector final
{
public:
    Syscollector(const std::chrono::milliseconds& timeout);
    void start();
    ~Syscollector();
private:
    void sync();
    const std::chrono::milliseconds m_timeout;
    std::atomic_bool                m_running;
    std::thread                     m_thread;
    SysInfo                         m_info;
};


#endif //_SYSCOLLECTOR_IMP_H