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
#include "isync_message_transport.hpp"

#include <atomic>
#include <chrono>
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
        /// @param syncEndDelay Delay for synchronization end message in seconds
        /// @param timeout Default timeout for synchronization operations.
        /// @param retries Default number of retries for synchronization operations.
        /// @param maxEps Default maximum events per second for synchronization operations.
        explicit AgentSyncProtocol(const std::string& moduleName, const std::string& dbPath, MQ_Functions mqFuncs, LoggerFunc logger, std::chrono::seconds syncEndDelay, std::chrono::seconds timeout,
                                   unsigned int retries, size_t maxEps, std::shared_ptr<IPersistentQueue> queue = nullptr);

        /// @copydoc IAgentSyncProtocol::persistDifference
        void persistDifference(const std::string& id,
                               Operation operation,
                               const std::string& index,
                               const std::string& data,
                               uint64_t version) override;

        /// @copydoc IAgentSyncProtocol::persistDifferenceInMemory
        void persistDifferenceInMemory(const std::string& id,
                                       Operation operation,
                                       const std::string& index,
                                       const std::string& data,
                                       uint64_t version) override;

        /// @copydoc IAgentSyncProtocol::synchronizeModule
        bool synchronizeModule(Mode mode, Option option = Option::SYNC) override;

        /// @copydoc IAgentSyncProtocol::requiresFullSync
        bool requiresFullSync(const std::string& index,
                              const std::string& checksum) override;

        /// @copydoc IAgentSyncProtocol::clearInMemoryData
        void clearInMemoryData() override;

        /// @copydoc IAgentSyncProtocol::synchronizeMetadataOrGroups
        bool synchronizeMetadataOrGroups(Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion) override;

        /// @copydoc IAgentSyncProtocol::notifyDataClean
        bool notifyDataClean(const std::vector<std::string>& indices, Option option = Option::SYNC) override;

        /// @copydoc IAgentSyncProtocol::deleteDatabase
        void deleteDatabase() override;

        /// @copydoc IAgentSyncProtocol::stop
        void stop() override;

        /// @brief Reset the stop flag to allow restarting operations
        /// This should be called when restarting the module after a stop
        void reset();

        /// @copydoc IAgentSyncProtocol::shouldStop
        bool shouldStop() const override;

        /// @brief Parses a FlatBuffer response message received from the manager.
        /// @param data Pointer to the FlatBuffer-encoded message buffer.
        /// @param length Size of the FlatBuffer message in bytes.
        /// @return true if the message was successfully parsed and processed; false otherwise.
        bool parseResponseBuffer(const uint8_t* data, size_t length) override;

    private:

        /// @brief Name of the module associated with this instance.
        std::string m_moduleName;

        /// @brief The message transport (MQueue or Router).
        std::unique_ptr<ISyncMessageTransport> m_transport;

        /// @brief Persistent message queue used to store and replay differences for synchronization.
        std::shared_ptr<IPersistentQueue> m_persistentQueue;

        /// @brief Logger function
        LoggerFunc m_logger;

        /// @brief Delay for synchronization end message in seconds
        std::chrono::seconds m_syncEndDelay;

        /// @brief Stop flag to abort ongoing operations
        std::atomic<bool> m_stopRequested{false};

        /// @brief In-memory vector to store PersistedData for recovery scenarios
        std::vector<PersistedData> m_inMemoryData;

        /// @brief Default timeout for synchronization operations
        std::chrono::seconds m_timeout;

        /// @brief Default number of retries for synchronization operations
        unsigned int m_retries;

        /// @brief Default maximum events per second for synchronization operations
        size_t m_maxEps;

        /// @brief Sends a start message to the server
        /// @param mode Sync mode
        /// @param dataSize Size of data to send
        /// @param uniqueIndices Vector of unique indices to be synchronized
        /// @param option Synchronization option.
        /// @param globalVersion Optional global version to include in the Start message
        /// @return True on success, false on failure or timeout
        bool sendStartAndWaitAck(Mode mode,
                                 size_t dataSize,
                                 const std::vector<std::string>& uniqueIndices,
                                 Option option = Option::SYNC,
                                 std::optional<uint64_t> globalVersion = std::nullopt);

        /// @brief Receives a startack message from the server
        /// @param timeout Timeout to wait for Ack
        /// @return True on success, false on failure
        bool receiveStartAck(std::chrono::seconds timeout);

        /// @brief Sends data messages to the server
        /// @param session Session id
        /// @param data Data to send
        /// @return True on success, false on failure
        bool sendDataMessages(uint64_t session,
                              const std::vector<PersistedData>& data);

        /// @brief Sends a checksum module message to the server
        /// @param session Session id
        /// @param index Index name
        /// @param checksum Checksum value
        /// @return True on success, false on failure
        bool sendChecksumMessage(uint64_t session,
                                 const std::string& index,
                                 const std::string& checksum);

        /// @brief Sends DataClean messages to the server for each data item
        /// @param session Session id
        /// @param data Vector of PersistedData to send as DataClean messages
        /// @return True on success, false on failure
        bool sendDataCleanMessages(uint64_t session,
                                   const std::vector<PersistedData>& data);

        /// @brief Sends an end message to the server
        /// @param session Session id
        /// @param dataToSync The complete vector of data items being synchronized in the current session.
        /// @return True on success, false on failure or timeout
        bool sendEndAndWaitAck(uint64_t session,
                               const std::vector<PersistedData>& dataToSync);

        /// @brief Receives an endack message from the server
        /// @param timeout Timeout to wait for Ack
        /// @return True on success, false on failure
        bool receiveEndAck(std::chrono::seconds timeout);

        /// @brief Sends a flatbuffer message as a string to the server
        /// @param fbData Flatbuffer data
        /// @return True on success, false on failure
        bool sendFlatBufferMessageAsString(const std::vector<uint8_t>& fbData);

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

        /// @brief Converts internal Mode enum to protocol schema Mode.
        /// @param mode The internal Mode enum value.
        /// @return The corresponding Wazuh::SyncSchema::Mode value.
        Wazuh::SyncSchema::Mode toProtocolMode(Mode mode) const;

        /// @brief Converts internal Option enum to protocol schema Option.
        /// @param option The internal Option enum value.
        /// @return The corresponding Wazuh::SyncSchema::Option value.
        Wazuh::SyncSchema::Option toProtocolOption(Option option) const;

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

            /// @brief Last sync operation result for detailed error reporting.
            SyncResult lastSyncResult = SyncResult::SUCCESS;

            /// @brief Destructor ensures all waiting threads are woken up before destruction.
            ///
            /// This prevents deadlocks when the condition variable is destroyed while threads are still waiting.
            ~SyncState()
            {
                std::lock_guard<std::mutex> lock(mtx);
                syncFailed = true;
                cv.notify_all();
            }

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
                lastSyncResult = SyncResult::SUCCESS;
            }
        };

        /// @brief Manages the state for the current synchronization operation.
        SyncState m_syncState;
};

#endif // AGENT_SYNC_PROTOCOL_HPP
