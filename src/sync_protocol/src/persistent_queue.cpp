#include "persistent_queue.hpp"
#include "persistent_queue_storage.hpp"

#include <algorithm>

PersistentQueue::PersistentQueue()
    : m_storage(std::make_shared<PersistentQueueStorage>())
{
    try
    {
        for (auto mod :
                {
                    "FIM", "SCA", "INV", "OTHER"
                })
        {
            m_seqCounter[mod] = 0;
            loadFromStorage(mod);
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Unexpected error: " << ex.what() << std::endl;
        throw;
    }
}

PersistentQueue::~PersistentQueue() = default;

uint64_t PersistentQueue::submit(const std::string& module, const std::string& id,
                                 const std::string& index,
                                 const std::string& data,
                                 Wazuh::SyncSchema::Operation operation)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t seq = ++m_seqCounter[module];
    PersistedData msg{seq, id, index, data, operation};
    m_store[module].push_back(msg);

    try
    {
        persistMessage(module, msg);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Error persisting message: " << ex.what() << std::endl;
        throw;
    }

    return seq;
}

std::optional<PersistedData> PersistentQueue::fetchNext(const std::string& module)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_store[module].empty())
    {
        return std::nullopt;
    }

    return m_store[module].front();
}

std::vector<PersistedData> PersistentQueue::fetchAll(const std::string& module)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<PersistedData> result;

    auto it = m_store.find(module);

    if (it != m_store.end())
    {
        result = it->second;
    }

    return result;
}

std::vector<PersistedData> PersistentQueue::fetchRange(
    const std::string& module,
    const std::vector<std::pair<uint64_t, uint64_t>>& ranges)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::vector<PersistedData> result;

    auto it = m_store.find(module);

    if (it == m_store.end())
    {
        return result;
    }

    for (const auto& data : it->second)
    {
        for (const auto& range : ranges)
        {
            if (data.seq >= range.first && data.seq <= range.second)
            {
                result.push_back(data);
                break;
            }
        }
    }

    return result;
}

void PersistentQueue::remove(const std::string& module, uint64_t sequence)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& queue = m_store[module];
    queue.erase(std::remove_if(queue.begin(), queue.end(), [&](const PersistedData & data)
    {
        return data.seq == sequence;
    }), queue.end());

    try
    {
        deleteMessage(module, sequence);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Error deleting message from database: " << ex.what() << std::endl;
        throw;
    }
}

void PersistentQueue::removeAll(const std::string& module)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    m_store[module].clear();
    m_seqCounter[module] = 0;

    try
    {
        deleteAllMessages(module);
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Error deleting all messages: " << ex.what() << std::endl;
        throw;
    }
}

void PersistentQueue::loadFromStorage(const std::string& module)
{
    try
    {
        const auto data = m_storage->loadAll(module);
        uint64_t maxSeq = 0;

        for (const auto& item : data)
        {
            m_store[module].push_back(item);
            maxSeq = std::max(maxSeq, item.seq);
        }

        m_seqCounter[module] = maxSeq;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[PersistentQueue] Error loading messages from database: " << ex.what() << std::endl;
        throw;
    }
}

void PersistentQueue::persistMessage(const std::string& module, const PersistedData& data)
{
    m_storage->save(module, data);
}

void PersistentQueue::deleteMessage(const std::string& module, uint64_t sequence)
{
    m_storage->remove(module, sequence);
}

void PersistentQueue::deleteAllMessages(const std::string& module)
{
    m_storage->removeAll(module);
}
