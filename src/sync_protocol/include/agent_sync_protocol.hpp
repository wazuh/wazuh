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

#include "agent_sync_protocol_c_interface.h"
#include "inventorySync_generated.h"
#include "ipersistent_queue.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <condition_variable>

class IAgentSyncProtocol
{
    public:
        /// @brief Persist a difference in the buffer
        /// @param module Module name
        /// @param id Difference id (hash ok PKs)
        /// @param operation Operation type
        /// @param index Index where to send the difference
        /// @param data Difference data
        virtual void persistDifference(const std::string& module,
                                       const std::string& id,
                                       Wazuh::SyncSchema::Operation operation,
                                       const std::string& index,
                                       const std::string& data) = 0;

        /// @brief Synchronize a module with the server
        /// @param module Module name
        /// @param mode Sync mode
        /// @param realtime Realtime sync
        virtual void synchronizeModule(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime) = 0;

        /// @brief Destructor
        virtual ~IAgentSyncProtocol() = default;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        virtual bool parseResponseBuffer(const uint8_t* data) = 0;
};

class AgentSyncProtocol : public IAgentSyncProtocol
{
    public:
        /// @brief Constructs the synchronization protocol handler.
        /// @param mqFuncs Functions used to interact with MQueue.
        /// @param queue Optional persistent queue to use for message storage and retrieval.
        explicit AgentSyncProtocol(MQ_Functions mqFuncs, std::shared_ptr<IPersistentQueue> queue = nullptr);

        /// @copydoc IAgentSyncProtocol::persistDifference
        void persistDifference(const std::string& module,
                               const std::string& id,
                               Wazuh::SyncSchema::Operation operation,
                               const std::string& index,
                               const std::string& data) override;

        /// @copydoc IAgentSyncProtocol::synchronizeModule
        void synchronizeModule(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime) override;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        bool parseResponseBuffer(const uint8_t* data) override;

    private:

        /// @brief Functions used to interact with MQueue.
        MQ_Functions m_mqFuncs;

        /// @brief Persistent message queue used to store and replay differences for synchronization.
        std::shared_ptr<IPersistentQueue> m_persistentQueue;

        /// @brief Queue
        int m_queue = -1;

        /// @brief Ensures that the queue is available
        /// @return True on success, false on failure
        bool ensureQueueAvailable();

        /// @brief Sends a start message to the server
        /// @param module Module name
        /// @param mode Sync mode
        /// @param realtime Realtime sync
        /// @param dataSize Size of data to send
        /// @return True on success, false on failure
        bool sendStartAndWaitAck(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime, size_t dataSize);

        /// @brief Receives a startack message from the server
        /// @param timeout Timeout to wait for Ack
        /// @return True on success, false on failure
        bool receiveStartAck(std::chrono::seconds timeout);

        /// @brief Sends data messages to the server
        /// @param module Module name
        /// @param session Session id
        /// @param data Data to send
        /// @return True on success, false on failure
        bool sendDataMessages(const std::string& module,
                              uint64_t session,
                              const std::vector<PersistedData>& data);

        /// @brief Sends an end message to the server
        /// @param module Module name
        /// @param session Session id
        /// @return True on success, false on failure
        bool sendEndAndWaitAck(const std::string& module, uint64_t session);

        /// @brief Receives an endack message from the server
        /// @return True on success, false on failure
        bool receiveEndAck();

        /// @brief Receives a reqret message from the server
        /// @return Ranges received
        std::vector<std::pair<uint64_t, uint64_t>> receiveReqRet();

        /// @brief Clears persisted differences for a module
        /// @param module Module name
        void clearPersistedDifferences(const std::string& module);

        /// @brief Sends a flatbuffer message as a string to the server
        /// @param fbData Flatbuffer data
        /// @param module Module name
        /// @return True on success, false on failure
        bool sendFlatBufferMessageAsString(const std::vector<uint8_t>& fbData, const std::string& module);

        /// @brief Defines the possible phases of a synchronization process.
        enum class SyncPhase
        {
            /// @brief The protocol is not in an active synchronization process.
            Idle,
            /// @brief A start message has been sent, waiting for the manager's StartAck.
            WaitingStartAck,
            /// @brief An end message has been sent, waiting for the manager's EndAck.
            WaitingEndAck
        };

        /// @brief Synchronization state shared between threads during module sync.
        ///
        /// This structure holds synchronization primitives and state flags used to
        /// coordinate between the main synchronization thread and the response handler.
        /// It stores whether specific acknowledgments have been received and the ranges
        /// requested by the manager.
        struct SyncState
        {
            /// @brief Mutex used to protect access to the synchronization state.
            std::mutex mtx;

            /// @brief Condition variable used to signal waiting threads.
            std::condition_variable cv;

            /// @brief Indicates whether a StartAck response has been received.
            bool startAckReceived = false;

            /// @brief Indicates whether an EndAck response has been received.
            bool endAckReceived = false;

            /// @brief Ranges requested by the manager via ReqRet message.
            std::vector<std::pair<uint64_t, uint64_t>> reqRetRanges;

            /// @brief Current phase of the synchronization process.
            SyncPhase phase = SyncPhase::Idle;

            /// @brief Unique identifier for the current synchronization session, received from the manager.
            uint64_t session = 0;

            /// @brief Resets all internal flags and clears received ranges.
            ///
            /// This should be called before starting a new synchronization cycle.
            void reset()
            {
                startAckReceived = false;
                endAckReceived = false;
                reqRetRanges.clear();
                phase = SyncPhase::Idle;
                session = 0;
            }
        };

        /// @brief Manages the state for the current synchronization operation.
        SyncState m_syncState;
};

#endif // AGENT_SYNC_PROTOCOL_HPP
