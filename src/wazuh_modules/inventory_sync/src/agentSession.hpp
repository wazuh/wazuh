#include "context.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "gapSet.hpp"
#include "responseDispatcher.hpp"
#include "rocksDBWrapper.hpp"
#include "threadDispatcher.h"
#include <functional>
#include <memory>
#include <string>
#include <utility>

enum class ResponseStatus : std::uint8_t
{
    Ok,
    Error,
};

struct Response
{
    ResponseStatus status;
    std::shared_ptr<Context> context;
};

using WorkersQueue = Utils::AsyncDispatcher<std::vector<char>, std::function<void(const std::vector<char>&)>>;
using ResponseQueue =
    Utils::AsyncDispatcher<::flatbuffers::Offset<Wazuh::SyncSchema::Message>,
                           std::function<void(const ::flatbuffers::Offset<Wazuh::SyncSchema::Message>&)>>;

using IndexerQueue = Utils::AsyncDispatcher<Response, std::function<void(const Response&)>>;

class AgentSessionException : public std::exception
{
public:
    explicit AgentSessionException(std::string message)
        : m_message(std::move(message))
    {
    }

    const char* what() const noexcept override
    {
        return m_message.c_str();
    }

private:
    std::string m_message;
};

class AgentSession final
{
    std::unique_ptr<GapSet> m_gapSet;
    std::shared_ptr<Context> m_context;
    Utils::RocksDBWrapper* m_store;
    IndexerQueue* m_indexerQueue;
    bool m_endReceived = false;

public:
    explicit AgentSession(const uint64_t sessionId,
                          Wazuh::SyncSchema::Start const* data,
                          Utils::RocksDBWrapper* store,
                          IndexerQueue* indexerQueue,
                          const ResponseDispatcher& responseDispatcher)
        : m_store {store}
        , m_indexerQueue {indexerQueue}

    {
        if (data == nullptr)
        {
            throw AgentSessionException("Invalid data");
        }
        // Create new session.
        if (data->size() == 0)
        {
            throw AgentSessionException("Invalid size");
        }
        m_gapSet = std::make_unique<GapSet>(data->size());

        if (data->module_() == nullptr)
        {
            throw AgentSessionException("Invalid module");
        }

        if (data->id() == 0)
        {
            throw AgentSessionException("Invalid id");
        }

        m_context = std::make_shared<Context>(Context {data->mode(), sessionId, data->id(), data->module_()->str()});

        responseDispatcher.sendStartAck(Wazuh::SyncSchema::Status_Ok, m_context);
    }

    void handleData(Wazuh::SyncSchema::Data const* data, const std::vector<char>& dataRaw)
    {
        const auto seq = data->seq();
        const auto session = data->session();

        m_store->put(std::to_string(session) + "_" + std::to_string(seq),
                     rocksdb::Slice(dataRaw.data(), dataRaw.size()));
        m_gapSet->observe(data->seq());

        if (m_endReceived)
        {
            if (m_gapSet->empty())
            {
                m_indexerQueue->push(Response({ResponseStatus::Ok, m_context}));
            }
        }
    }

    void handleEnd(const ResponseDispatcher& responseDispatcher)
    {
        if (m_gapSet->empty())
        {
            m_indexerQueue->push(Response({ResponseStatus::Ok, m_context}));
        }
        else
        {
            responseDispatcher.sendEndMissingSeq(m_context->sessionId, m_gapSet->ranges());
        }
    }
};
