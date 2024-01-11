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
#ifndef _AGENT_EMULATOR_H_
#define _AGENT_EMULATOR_H_

#include <memory>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include "threadSafeQueue.h"
#include "rsync.h"
#include "dbsync.h"


using SyncId = RSYNC_HANDLE;
using SyncData = std::vector<unsigned char>;
using SyncMessage = std::pair<SyncId, SyncData>;
using SyncQueue = Utils::SafeQueue<SyncMessage>;

class AgentEmulator
{
    public:
        AgentEmulator(const std::chrono::milliseconds updatePeriod,
                      const unsigned int maxDbItems,
                      const std::shared_ptr<SyncQueue>& outQueue,
                      const std::string& dbFolder,
                      const size_t maxQueueSize);
        ~AgentEmulator();
    private:

        void updateData();
        void syncData(const void* buffer, size_t bufferSize);
        static void agentEmulatorSyncCallback(const void* buffer, size_t bufferSize, void* userData);

        const std::string m_agentId;
        const RSYNC_HANDLE m_rsyncHandle;
        const DBSYNC_HANDLE m_dbSyncHandle;
        const cJSON* m_config;
        const cJSON* m_startConfig;
        const std::chrono::milliseconds m_updatePeriod;
        const unsigned int m_maxDbItems;
        std::atomic_bool m_threadsRunning;
        std::thread m_updateThread;
        const std::shared_ptr<SyncQueue> m_outQueue;
};


#endif //_AGENT_EMULATOR_H_