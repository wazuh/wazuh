/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AGENT_SYNC_PROTOCOL_HPP
#define AGENT_SYNC_PROTOCOL_HPP

#include "inventorySync_generated.h"
#include "ipersistent_queue.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

class IAgentSyncProtocol
{
    public:
        virtual void persistDifference(const std::string& module,
                                       const std::string& id,
                                       Wazuh::SyncSchema::Operation operation,
                                       const std::string& index,
                                       const std::string& data) = 0;

        virtual void synchronizeModule(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime) = 0;

        virtual ~IAgentSyncProtocol() = default;
};

class AgentSyncProtocol : public IAgentSyncProtocol
{
    public:
        explicit AgentSyncProtocol(std::shared_ptr<IPersistentQueue> queue = nullptr);

        void persistDifference(const std::string& module,
                               const std::string& id,
                               Wazuh::SyncSchema::Operation operation,
                               const std::string& index,
                               const std::string& data) override;

        void synchronizeModule(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime) override;

    private:

        std::shared_ptr<IPersistentQueue> m_persistentQueue;

        bool sendStartAndWaitAck(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime, uint64_t& session, const std::vector<PersistedData>& data);

        void sendDataMessages(uint64_t session,
                              const std::vector<PersistedData>& data);

        void sendEnd(uint64_t session);
        void sendFlatBufferMessageAsString(flatbuffers::span<uint8_t> fbData);
        void clearPersistedDifferences(const std::string& module);

        // Simulated server communication
        std::vector<std::pair<uint64_t, uint64_t>> receiveReqRet();
        bool receiveEndAck(bool& success);
};

#endif // AGENT_SYNC_PROTOCOL_HPP
