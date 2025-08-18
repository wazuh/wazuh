#ifndef _AGENT_SESSION_HPP
#define _AGENT_SESSION_HPP

#include "context.hpp"
#include "flatbuffers/include/inventorySync_generated.h"
#include "gapSet.hpp"
#include "responseDispatcher.hpp"
#include "rocksDBWrapper.hpp"
#include "threadDispatcher.h"
#include <charconv>
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

template<typename TStore, typename TIndexerQueue, typename TResponseDispatcher>
class AgentSessionImpl final
{
    std::unique_ptr<GapSet> m_gapSet;
    std::shared_ptr<Context> m_context;
    TStore& m_store;
    TIndexerQueue& m_indexerQueue;
    bool m_endReceived = false;
    std::mutex m_mutex;

public:
    explicit AgentSessionImpl(const uint64_t sessionId,
                              std::string_view agentId,
                              std::string_view moduleName,
                              Wazuh::SyncSchema::Start const* data,
                              TStore& store,
                              TIndexerQueue& indexerQueue,
                              const TResponseDispatcher& responseDispatcher)
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

        uint64_t agentIdConverted {};

        auto [ptr, ec] = std::from_chars(agentId.data(), agentId.data() + agentId.size(), agentIdConverted);

        if (ec == std::errc::result_out_of_range)
        {
            throw AgentSessionException("Agent ID out of range");
        }

        if (ec == std::errc::invalid_argument)
        {
            throw AgentSessionException("Agent ID invalid argument");
        }

        m_gapSet = std::make_unique<GapSet>(data->size());

        m_context =
            std::make_shared<Context>(Context {.mode = data->mode(),
                                               .sessionId = sessionId,
                                               .agentId = agentIdConverted,
                                               .moduleName = std::string(moduleName.data(), moduleName.size())});

        std::cout << "AgentSessionImpl: " << m_context->sessionId << " " << m_context->agentId << " "
                  << m_context->moduleName << std::endl;

        responseDispatcher.sendStartAck(Wazuh::SyncSchema::Status_Ok, m_context);
    }

    void handleData(Wazuh::SyncSchema::Data const* data, const std::vector<char>& dataRaw)
    {
        const auto seq = data->seq();
        const auto session = data->session();

        m_store.put(std::to_string(session) + "_" + std::to_string(seq),
                    rocksdb::Slice(dataRaw.data(), dataRaw.size()));

        std::lock_guard<std::mutex> lock(m_mutex);
        m_gapSet->observe(data->seq());

        // std::cout << "Data received: " << std::to_string(session) + "_" + std::to_string(seq) << "\n";

        if (m_endReceived)
        {
            if (m_gapSet->empty())
            {
                m_indexerQueue.push(Response({.status = ResponseStatus::Ok, .context = m_context}));
            }
        }
    }

    void handleEnd(const TResponseDispatcher& responseDispatcher)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_endReceived = true;
        if (m_gapSet->empty())
        {
            std::cout << "End received and gap set is empty\n";
            m_indexerQueue.push(Response({.status = ResponseStatus::Ok, .context = m_context}));
        }
        else
        {
            responseDispatcher.sendEndMissingSeq(m_context->sessionId, m_gapSet->ranges());
        }
    }
};

using AgentSession = AgentSessionImpl<Utils::RocksDBWrapper, IndexerQueue, ResponseDispatcher>;

#endif // _AGENT_SESSION_HPP
