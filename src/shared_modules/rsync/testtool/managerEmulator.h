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
#ifndef _MANAGER_EMULATOR_H_
#define _MANAGER_EMULATOR_H_

#include <memory>
#include <thread>
#include <chrono>
#include <atomic>
#include "threadSafeQueue.h"
#include "agentEmulator.h"

class ManagerEmulator
{
    public:
        ManagerEmulator(const std::shared_ptr<SyncQueue>& inQueue);
        ~ManagerEmulator();
    private:

        void syncData();

        const std::shared_ptr<SyncQueue> m_inQueue;
        std::thread m_syncThread;
        std::atomic_bool m_threadRunning;
};


#endif //_MANAGER_EMULATOR_H_