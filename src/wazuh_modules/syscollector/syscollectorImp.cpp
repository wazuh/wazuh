/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollectorImp.h"
#include <iostream>

Syscollector::Syscollector(const std::chrono::milliseconds& timeout)
: m_timeout{timeout}
, m_running{true}
, m_thread{std::bind(&Syscollector::sync, this)}
{
}


Syscollector::~Syscollector()
{
    m_running = false;
    if (m_thread.joinable())
    {
        m_thread.join();
    }
}

void Syscollector::start()
{
    while(m_running)
    {
        const auto& hw{m_info.hardware()};
        const auto& packages{m_info.packages()};
        const auto& processes{m_info.processes()};        
        std::cout << packages.dump() << std::endl;
        std::cout << hw.dump() << std::endl;
        std::cout << processes.dump() << std::endl;
        std::this_thread::sleep_for(m_timeout);
    }
}

void Syscollector::sync()
{
    while(m_running)
    {
        std::this_thread::sleep_for(m_timeout);
    }
}
