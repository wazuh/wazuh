#pragma once

#include "iagent_sync_protocol.hpp"

#include <gmock/gmock.h>

#include <string>
#include <vector>

class MockAgentSyncProtocol : public IAgentSyncProtocol
{
    public:
        MOCK_METHOD(void,
                    persistDifference,
                    (const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version, bool isDataContext),
                    (override));

        MOCK_METHOD(void,
                    persistDifferenceInMemory,
                    (const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version),
                    (override));

        MOCK_METHOD(bool, synchronizeModule, (Mode mode, Option option), (override));

        MOCK_METHOD(bool, requiresFullSync, (const std::string& index, const std::string& checksum), (override));

        MOCK_METHOD(void, clearInMemoryData, (), (override));

        MOCK_METHOD(bool, synchronizeMetadataOrGroups, (Mode mode, const std::vector<std::string>& indices, uint64_t globalVersion), (override));

        MOCK_METHOD(bool, notifyDataClean, (const std::vector<std::string>& indices, Option option), (override));

        MOCK_METHOD(bool, sendDataContextMessages, (uint64_t session, const std::vector<PersistedData>& data), (override));

        MOCK_METHOD(std::vector<PersistedData>, fetchPendingItems, (bool onlyDataValues), (override));

        MOCK_METHOD(void, clearAllDataContext, (), (override));

        MOCK_METHOD(void, deleteDatabase, (), (override));

        MOCK_METHOD(void, stop, (), (override));

        MOCK_METHOD(void, reset, (), (override));

        MOCK_METHOD(bool, shouldStop, (), (const, override));

        MOCK_METHOD(bool, parseResponseBuffer, (const uint8_t* data, size_t length), (override));
};
