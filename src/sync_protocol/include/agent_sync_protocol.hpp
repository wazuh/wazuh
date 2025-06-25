#ifndef AGENT_SYNC_PROTOCOL_HPP
#define AGENT_SYNC_PROTOCOL_HPP

#include "inventorySync_generated.h"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

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
};

class AgentSyncProtocol : public IAgentSyncProtocol
{
public:
    /// @copydoc IAgentSyncProtocol::persistDifference
    void persistDifference(const std::string& module,
                           const std::string& id,
                           Wazuh::SyncSchema::Operation operation,
                           const std::string& index,
                           const std::string& data) override;

    /// @copydoc IAgentSyncProtocol::synchronizeModule
    void synchronizeModule(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime) override;

private:
    struct PersistedData
    {
        uint64_t seq;
        std::string id;
        std::string index;
        std::string data;
        Wazuh::SyncSchema::Operation operation;
    };

    /// @brief Data buffer
    std::unordered_map<std::string, std::vector<PersistedData>> m_data;

    /// @brief Sequence counter
    uint64_t m_seqCounter = 0;

    /// @brief Queue
    int m_queue = -1;

    /// @brief Ensures that the queue is available
    /// @return True on success, false on failure
    bool ensureQueueAvailable();

    /// @brief Sends a start message to the server
    /// @param module Module name
    /// @param mode Sync mode
    /// @param realtime Realtime sync
    /// @param session Session id reference
    /// @return True on success, false on failure
    bool sendStartAndWaitAck(const std::string& module, Wazuh::SyncSchema::Mode mode, bool realtime, uint64_t& session);

    /// @brief Receives a startack message from the server
    /// @param session Session id reference
    /// @return True on success, false on failure
    bool receiveStartAck(uint64_t& session);

    /// @brief Sends data messages to the server
    /// @param module Module name
    /// @param session Session id
    /// @param ranges Ranges to send
    /// @return True on success, false on failure
    bool sendDataMessages(const std::string& module,
                          uint64_t session,
                          const std::vector<std::pair<uint64_t, uint64_t>>* ranges = nullptr);

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
    bool sendFlatBufferMessageAsString(flatbuffers::span<uint8_t> fbData, const std::string& module);
};

#endif // AGENT_SYNC_PROTOCOL_HPP
