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

#include "agent_sync_protocol_c_interface_types.h"
#include "agent_sync_protocol_types.hpp"
#include "iagent_sync_protocol.hpp"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <unordered_map>
#include <vector>
#include <condition_variable>
class AgentSyncProtocol : public IAgentSyncProtocol
{
    public:
        /// @brief Constructs the synchronization protocol handler.
        /// @param moduleName Name of the module associated with this instance.
        /// @param dbPath Path to the SQLite database file for this protocol instance.
        /// @param mqFuncs Functions used to interact with MQueue.
        /// @param logger Logger function
        /// @param queue Optional persistent queue to use for message storage and retrieval.
        explicit AgentSyncProtocol(const std::string& moduleName, const std::string& dbPath, MQ_Functions mqFuncs, LoggerFunc logger, std::shared_ptr<IPersistentQueue> queue = nullptr);

        /// @copydoc IAgentSyncProtocol::persistDifference
        void persistDifference(const std::string& id,
                               Operation operation,
                               const std::string& index,
                               const std::string& data) override;

        /// @copydoc IAgentSyncProtocol::synchronizeModule
        bool synchronizeModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps) override;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @param length Size of the FlatBuffer message in bytes.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        bool parseResponseBuffer(const uint8_t* data, size_t length) override;

    private:

        /// @brief Name of the module associated with this instance.
        std::string m_moduleName;

        /// @brief Functions used to interact with MQueue.
        MQ_Functions m_mqFuncs;

        /// @brief Persistent message queue used to store and replay differences for synchronization.
        std::shared_ptr<IPersistentQueue> m_persistentQueue;

        /// @brief Logger function
        LoggerFunc m_logger;

        /// @brief Queue
        int m_queue = -1;

        /// @brief Sent message counter for eps control
        std::atomic<size_t> m_msgSent{0};

        /// @brief Ensures that the queue is available
        /// @return True on success, false on failure
        bool ensureQueueAvailable();

        /// @brief Sends a start message to the server
        /// @param mode Sync mode
        /// @param dataSize Size of data to send
        /// @param timeout The timeout for each response wait.
        /// @param retries The maximum number of re-send attempts.
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return True on success, false on failure or timeout
        bool sendStartAndWaitAck(Mode mode,
                                 size_t dataSize,
                                 const std::chrono::seconds timeout,
                                 unsigned int retries,
                                 size_t maxEps);

        /// @brief Receives a startack message from the server
        /// @param timeout Timeout to wait for Ack
        /// @return True on success, false on failure
        bool receiveStartAck(std::chrono::seconds timeout);

        /// @brief Sends data messages to the server
        /// @param session Session id
        /// @param data Data to send
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return True on success, false on failure
        bool sendDataMessages(uint64_t session,
                              const std::vector<PersistedData>& data,
                              size_t maxEps);

        /// @brief Sends an end message to the server
        /// @param session Session id
        /// @param timeout The timeout for each response wait.
        /// @param retries The maximum number of re-send attempts.
        /// @param dataToSync The complete vector of data items being synchronized in the current session.
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return True on success, false on failure or timeout
        bool sendEndAndWaitAck(uint64_t session,
                               const std::chrono::seconds timeout,
                               unsigned int retries,
                               const std::vector<PersistedData>& dataToSync,
                               size_t maxEps);

        /// @brief Receives an endack message from the server
        /// @param timeout Timeout to wait for Ack
        /// @return True on success, false on failure
        bool receiveEndAck(std::chrono::seconds timeout);

        /// @brief Sends a flatbuffer message as a string to the server
        /// @param fbData Flatbuffer data
        /// @param maxEps The maximum event reporting throughput. 0 means disabled.
        /// @return True on success, false on failure
        bool sendFlatBufferMessageAsString(const std::vector<uint8_t>& fbData, size_t maxEps);

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

        /// @brief Validate phase and session
        /// @param receivedPhase Received synchronization phase
        /// @param incomingSession Session received in message
        /// @return True if current phase and session match the expected ones
        bool validatePhaseAndSession(const SyncPhase receivedPhase, const uint64_t incomingSession);

        /// @brief Safely resets the synchronization state by acquiring a lock.
        void clearSyncState();

        /// @brief Filters a vector of persisted data based on a list of sequence number ranges.
        /// @param sourceData The complete vector of `PersistedData` items.
        /// @param ranges A vector of pairs [begin, end] inclusive range of sequence numbers.
        /// @return A new vector containing only the `PersistedData` items that match the requested ranges.
        std::vector<PersistedData> filterDataByRanges(
            const std::vector<PersistedData>& sourceData,
            const std::vector<std::pair<uint64_t, uint64_t>>& ranges);

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

            /// @brief Indicates that a ReqRet message has been received.
            bool reqRetReceived = false;

            /// @brief Indicates that the manager reported a error, forcing the sync to fail.
            bool syncFailed = false;

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
                reqRetReceived = false;
                syncFailed = false;
                reqRetRanges.clear();
                phase = SyncPhase::Idle;
                session = 0;
            }
        };

        /// @brief Manages the state for the current synchronization operation.
        SyncState m_syncState;
};

#endif // AGENT_SYNC_PROTOCOL_HPP
