#pragma once

#include "agentSession.hpp"
#include "context.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include <gmock/gmock.h>
#include <string>
#include <vector>

// Mock for TStore (rocksdb::DB)
class MockStore
{
public:
    virtual ~MockStore() = default;
    MOCK_METHOD(void, put, (const std::string& key, const rocksdb::Slice& value));
};

// Mock for TIndexerQueue
class MockIndexerQueue
{
public:
    virtual ~MockIndexerQueue() = default;
    MOCK_METHOD(void, push, (const Response& response));
};

// Mock for TResponseDispatcher
class MockResponseDispatcher
{
public:
    virtual ~MockResponseDispatcher() = default;
    MOCK_METHOD(void, sendStartAck, (Wazuh::SyncSchema::Status status, std::shared_ptr<Context> context), (const));
    MOCK_CONST_METHOD2(sendEndMissingSeq,
                       void(uint64_t sessionId, const std::vector<std::pair<uint64_t, uint64_t>>& ranges));
};
