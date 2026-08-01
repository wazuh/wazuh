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

#include "agent_sync_protocol_types.hpp"
#include "iagent_sync_protocol.hpp"
#include "sync_socket_transport.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <vector>

class AgentSyncProtocol : public IAgentSyncProtocol
{
    public:
        /// @brief Constructs the synchronization protocol handler.
        /// @param moduleName Name of the module associated with this instance.
        /// @param dbPath Optional path to the SQLite database file for this protocol instance. If not provided, only in-memory synchronization is available.
        /// @param logger Logger function
        /// @param timeout Default timeout for synchronization operations.
        /// @param retries Default number of retries for synchronization operations.
        /// @param queue Optional persistent queue to use for message storage and retrieval.
        /// @param syncTransport Optional carrier for whole sessions; defaults to the queue-sync socket.
        explicit AgentSyncProtocol(const std::string& moduleName, std::optional<std::string> dbPath, LoggerFunc logger,
                                   std::shared_ptr<IPersistentQueue> queue = nullptr,
                                   std::shared_ptr<ISyncSessionTransport> syncTransport = nullptr);

        /// @copydoc IAgentSyncProtocol::persistDifference
        void persistDifference(const std::string& id,
                               Operation operation,
                               const std::string& index,
                               const std::string& data,
                               uint64_t version,
                               bool isDataContext = false) override;

        /// @copydoc IAgentSyncProtocol::persistDifferenceInMemory
        void persistDifferenceInMemory(const std::string& id,
                                       Operation operation,
                                       const std::string& index,
                                       const std::string& data,
                                       uint64_t version) override;

        /// @copydoc IAgentSyncProtocol::synchronizeModule
        SyncModuleResult synchronizeModule(Mode mode, Option option = Option::SYNC) override;

        /// @copydoc IAgentSyncProtocol::requiresFullSync
        bool requiresFullSync(const std::string& index,
                              const std::string& checksum) override;

        /// @copydoc IAgentSyncProtocol::clearInMemoryData
        void clearInMemoryData() override;

        /// @copydoc IAgentSyncProtocol::synchronizeMetadataOrGroups
        SyncModuleResult synchronizeMetadataOrGroups(Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion) override;

        /// @copydoc IAgentSyncProtocol::notifyDataClean
        bool notifyDataClean(const std::vector<std::string>& indices, Option option = Option::SYNC) override;

        /// @copydoc IAgentSyncProtocol::fetchPendingItems
        std::vector<PersistedData> fetchPendingItems(bool onlyDataValues = true) override;

        /// @copydoc IAgentSyncProtocol::clearAllDataContext
        void clearAllDataContext() override;

        /// @copydoc IAgentSyncProtocol::deleteDatabase
        void deleteDatabase() override;

        /// @copydoc IAgentSyncProtocol::stop
        void stop() override;

        /// @brief Reset the stop flag to allow restarting operations
        /// This should be called when restarting the module after a stop
        void reset() override;

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

        /// @brief Carries a whole session to the agent over the queue-sync STREAM
        ///        socket, which has no 64 KB bound.
        std::shared_ptr<ISyncSessionTransport> m_syncTransport;

        /// @brief Persistent message queue used to store and replay differences for synchronization.
        std::shared_ptr<IPersistentQueue> m_persistentQueue;

        /// @brief Logger function
        LoggerFunc m_logger;

        /// @brief Stop flag to abort ongoing operations
        std::atomic<bool> m_stopRequested{false};

        /// @brief In-memory vector to store PersistedData for recovery scenarios
        std::vector<PersistedData> m_inMemoryData;

        /// @brief Retries for the local sync-socket hand-off.
        ///
        /// How many times runSession() re-submits to the HTTPS transport's intake
        /// socket when that socket is transiently unavailable (e.g. agentd restart).
        /// Fixed; the HTTP-level retry count lives in the transport layer.
        static constexpr unsigned int SYNC_HANDOFF_RETRIES = 3;

        /// @brief Updates the consecutive-failure streak with the outcome of a synchronization.
        /// @param success Whether the synchronization succeeded.
        /// @param stopped Whether it was aborted because a stop was requested.
        /// @return Consecutive failed synchronizations including this one, or 0 on success.
        ///
        /// A stop-induced abort leaves the streak untouched: it reports nothing about the manager.
        unsigned int trackSyncOutcome(bool success, bool stopped);

        /// @brief Waits for agent metadata to become available - indefinitely,
        ///        unless a stop is requested - then builds the Start table into
        ///        an existing FlatBuffer builder. Owns the metadata lifetime end
        ///        to end.
        /// @param builder Builder to emit the table into.
        /// @param mode Sync mode
        /// @param dataSize Size of data to send
        /// @param uniqueIndices Vector of unique indices to be synchronized
        /// @param option Synchronization option.
        /// @param globalVersion Optional global version to include in the Start message
        /// @return The Start offset, or a null offset when metadata or groups are
        ///         unavailable, or a stop was requested.
        flatbuffers::Offset<Wazuh::SyncSchema::Start> waitMetadataAndBuildStart(
            flatbuffers::FlatBufferBuilder& builder,
            Mode mode,
            size_t dataSize,
            const std::vector<std::string>& uniqueIndices,
            Option option = Option::SYNC,
            std::optional<uint64_t> globalVersion = std::nullopt);

        /// @brief One checksum declaration inside a session.
        struct ChecksumEntry
        {
            std::string index;
            std::string checksum;
        };

        /// @brief Everything a session carries. All four flows (module sync,
        ///        metadata/groups, integrity check, data clean) differ only in
        ///        which of these are populated, so they all go through
        ///        runSession() and produce one FullSession message. The size
        ///        announced in Start is derived from the item vectors.
        struct SessionContent
        {
            Mode mode {Mode::DELTA};
            std::vector<std::string> indices;
            Option option {Option::SYNC};
            std::optional<uint64_t> globalVersion;
            std::vector<PersistedData> dataValues;
            std::vector<PersistedData> dataContexts;
            std::vector<PersistedData> dataCleans;
            std::vector<ChecksumEntry> checksums;
        };

        /// @brief Sends one whole session and waits for the manager's answer.
        ///        Retries resend the entire session under the same id, which is
        ///        what makes the retry safe: the manager dedups on it.
        /// @param content What the session carries.
        /// @return True when the manager accepted it.
        bool runSession(const SessionContent& content);

        /// @brief Whether this synchronization option must bypass FullSession size capping.
        bool isUncappedSyncOption(Option option) const;

        /// @brief Splits DELTA sync into capped FullSessions by fetching blocks from the queue.
        SyncModuleResult synchronizeDeltaByBlocks(Option option);

        /// @brief Applies HTTP-result outcomes received from https_client callback routing.
        /// @param resultCode HTTP status code (0 = success).
        /// @param expectedSession Session that this result belongs to; 0 skips validation
        ///        (legacy path). The check is performed under m_syncState.mtx so it is
        ///        race-free with a concurrent session start.
        bool applyHttpResultCode(int resultCode, uint64_t expectedSession = 0);

        /// @brief Picks the id for a new session. The agent chooses it because the
        ///        single-message exchange has no StartAck to carry one back; a retry
        ///        reuses the same value so the manager can dedup on it.
        /// @return A session id unique within this agent.
        static uint64_t nextSessionId();

        /// @brief Serializes a whole session as one FullSession message.
        /// @param content What the session carries.
        /// @return The serialized message, or an empty vector on failure.
        std::vector<uint8_t> buildFullSessionMessage(const SessionContent& content);

        /// @brief Defines the possible phases of a synchronization process.
        enum class SyncPhase
        {
            /// @brief The protocol is not in an active synchronization process.
            Idle,
            /// @brief The session has been sent, waiting for the manager's answer.
            WaitingResponse
        };

        /// @brief Safely resets the synchronization state by acquiring a lock.
        void clearSyncState();

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

            /// @brief Indicates whether a terminal response has been received.
            bool responseReceived = false;

            /// @brief Indicates that the manager reported a error, forcing the sync to fail.
            bool syncFailed = false;

            /// @brief Current phase of the synchronization process.
            SyncPhase phase = SyncPhase::Idle;

            /// @brief Last sync operation result for detailed error reporting.
            SyncResult lastSyncResult = SyncResult::SUCCESS;

            /// @brief True when the manager did not answer the handshake or reported itself Offline.
            /// Set only where that condition is known, since a SyncResult value alone does not identify
            /// it (COMMUNICATION_ERROR is also used for a local send failure in the middle of an
            /// established session).
            bool lastSyncManagerNotReady = false;

            /// @brief True when the in-flight session is an integrity check; non-200 means checksum mismatch.
            bool expectingChecksumResult = false;

            /// @brief Numeric session ID of the current in-flight session.
            ///
            /// Set by runSession() before the first send attempt and cleared on reset().
            /// applyHttpResultCode() validates incoming HCRESULT payloads against this
            /// value so that a stale response from a previous (timed-out) session cannot
            /// satisfy a newer one.
            uint64_t currentSession = 0;

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
                responseReceived = false;
                syncFailed = false;
                phase = SyncPhase::Idle;
                lastSyncResult = SyncResult::SUCCESS;
                lastSyncManagerNotReady = false;
                expectingChecksumResult = false;
                currentSession = 0;
            }
        };

        /// @brief Manages the state for the current synchronization operation.
        SyncState m_syncState;

        /// @brief Guards against concurrent calls to synchronizeModule().
        ///
        /// AsyncFlushController spawns a background thread that calls synchronizeModule()
        /// on the same instance as the module's periodic timer thread. If a sync is already
        /// in progress the second caller skips its cycle — the in-flight sync drains the
        /// shared queue, making the concurrent call redundant.
        std::atomic<bool> m_syncInProgress{false};

        /// @brief Consecutive failed synchronizations for this module, reset on the first success.
        ///
        /// Lives on the instance, not in SyncState, because SyncState is cleared at the start of every
        /// cycle. It is what tells a brief post-restart hiccup (the count stays at one and clears on the
        /// next cycle) apart from a lasting condition such as the manager having no indexer available
        /// (the count keeps growing), which the modules must keep reporting at WARNING.
        ///
        /// The streak is counted in sync ATTEMPTS that reach the handshake, not in cycles, and it is
        /// per protocol instance. When several sync flows share one instance (agent-info: metadata,
        /// groups and the integrity check; FIM: the periodic and the agent-info-requested syncs;
        /// SCA/Syscollector: the periodic sync and the flush), each of them bumps this same counter,
        /// so the SYNC_MANAGER_NOT_READY_TOLERANCE threshold can be reached in fewer real cycles for
        /// those modules than for a single-flow one. Only outcomes that reach the handshake move the
        /// counter: early returns (queue-open failure, nothing-to-sync success, invalid mode) leave it
        /// untouched, so "consecutive" is not strictly "consecutive cycles". This is acceptable because
        /// managerNotReady is a manager-wide condition: a real success means the manager is ready, and
        /// resetting the streak on it is correct regardless of which flow observed it.
        std::atomic<unsigned int> m_consecutiveSyncFailures{0};

        static constexpr size_t FULLSESSION_MAX_BYTES = 5U * 1024U * 1024U;
        static constexpr size_t FULLSESSION_PREFILTER_GRACE_BYTES = 64U * 1024U;
        static constexpr size_t FULLSESSION_MAX_BLOCKS_PER_SYNC = 10U;
        static constexpr std::string_view HTTP_RESULT_PREFIX = "HCRESULT:";
};

#endif // AGENT_SYNC_PROTOCOL_HPP
