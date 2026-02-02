#pragma once

#include <idbsync.hpp>

#include <gmock/gmock.h>

class MockDBSync : public IDBSync
{
    public:
        MOCK_METHOD(void, addTableRelationship, (const nlohmann::json& jsInput), (override));
        MOCK_METHOD(void, insertData, (const nlohmann::json& jsInsert), (override));
        MOCK_METHOD(void, setTableMaxRow, (const std::string& table, const long long maxRows), (override));
        MOCK_METHOD(void, syncRow, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
        MOCK_METHOD(void, selectRows, (const nlohmann::json& jsInput, ResultCallbackData callbackData), (override));
        MOCK_METHOD(void, deleteRows, (const nlohmann::json& jsInput), (override));
        MOCK_METHOD(void, updateWithSnapshot, (const nlohmann::json& jsInput, nlohmann::json& jsResult), (override));
        MOCK_METHOD(void,
                    updateWithSnapshot,
                    (const nlohmann::json& jsInput, ResultCallbackData callbackData),
                    (override));
        MOCK_METHOD(DBSYNC_HANDLE, handle, (), (override));
        MOCK_METHOD(void, closeAndDeleteDatabase, (), (override));
        MOCK_METHOD(std::string, getConcatenatedChecksums, (const std::string& tableName), (override));
        MOCK_METHOD(std::string,
                    getConcatenatedChecksums,
                    (const std::string& tableName, const std::string& rowFilter),
                    (override));
        MOCK_METHOD(std::string, calculateTableChecksum, (const std::string& tableName), (override));
        MOCK_METHOD(std::string,
                    calculateTableChecksum,
                    (const std::string& tableName, const std::string& rowFilter),
                    (override));
        MOCK_METHOD(void, increaseEachEntryVersion, (const std::string& tableName), (override));
        MOCK_METHOD(void,
                    increaseEachEntryVersion,
                    (const std::string& tableName, const std::string& rowFilter),
                    (override));
        MOCK_METHOD(std::vector<nlohmann::json>, getEveryElement, (const std::string& tableName), (override));
};
