/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * August 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <iostream>
#include "managerEmulator.h"

ManagerEmulator::ManagerEmulator(const std::shared_ptr<SyncQueue>& inQueue)
    : m_inQueue{ inQueue }
    , m_threadRunning{ true }
{
    m_syncThread = std::thread{&ManagerEmulator::syncData, this};
}

ManagerEmulator::~ManagerEmulator()
{
    m_threadRunning = false;

    if (m_syncThread.joinable())
    {
        m_syncThread.join();
    }
}

void ManagerEmulator::syncData()
{
    while (m_threadRunning)
    {
        SyncMessage msg;

        if (m_inQueue->pop(msg, false))
        {
            std::cout << "MGR: syncData: " << msg.first << std::endl;
            //TODO: check received data and apply changes to local db.
            rsync_push_message(msg.first, msg.second.data(), msg.second.size());
        }

        std::this_thread::yield();
    }
}
