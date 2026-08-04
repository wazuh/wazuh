#ifndef _MOCK_AGENT_SESSION_HPP
#define _MOCK_AGENT_SESSION_HPP

#include "agentSession.hpp"
#include "context.hpp"
#include "inventorySync_generated.h"
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

// Mock for TResponseDispatcher. TODO(#38117): StartAck/EndAck removed from FlatBuffer
// schema/agent side - the manager no longer acknowledges sessions via either, so this
// mock has no methods left. Kept as a type for AgentSessionImpl's template parameter.
class MockResponseDispatcher
{
public:
    virtual ~MockResponseDispatcher() = default;
};

#endif // _MOCK_AGENT_SESSION_HPP
