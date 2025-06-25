#include "persistent_queue.hpp"

#include <algorithm>

PersistentQueue::PersistentQueue() {
    for (auto mod : {ModuleType::FIM, ModuleType::SCA, ModuleType::INV, ModuleType::OTHER}) {
        m_seqCounter[mod] = 0;
        loadFromStorage(mod);
    }
}

PersistentQueue::~PersistentQueue() = default;

uint64_t PersistentQueue::submit(ModuleType module, const std::string& id,
                                 const std::string& index,
                                 const std::string& data,
                                 Wazuh::SyncSchema::Operation operation) {
    std::lock_guard<std::mutex> lock(m_mutex);
    uint64_t seq = ++m_seqCounter[module];
    PersistedData msg{seq, id, index, data, operation};
    m_store[module].push_back(msg);
    persistMessage(msg);
    return seq;
}

std::optional<PersistedData> PersistentQueue::fetchNext(ModuleType module) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_store[module].empty()) {
        return std::nullopt;
    }
    return m_store[module].front();
}

void PersistentQueue::remove(ModuleType module, uint64_t sequence) {
    std::lock_guard<std::mutex> lock(m_mutex);
    auto& queue = m_store[module];
    queue.erase(std::remove_if(queue.begin(), queue.end(), [&](const PersistedData& data) {
        return data.seq == sequence;
    }), queue.end());
    deleteMessage(module, sequence);
}

void PersistentQueue::loadFromStorage([[maybe_unused]] ModuleType module) {
    // Placeholder: Load messages from persistent store (e.g., dbsync)
    // For now, this does nothing
}

void PersistentQueue::persistMessage([[maybe_unused]] const PersistedData& data) {
    // Placeholder: Persist message to storage
    // For now, this does nothing
}

void PersistentQueue::deleteMessage([[maybe_unused]] ModuleType module, [[maybe_unused]] uint64_t sequence) {
    // Placeholder: Remove message from persistent storage
    // For now, this does nothing
}
