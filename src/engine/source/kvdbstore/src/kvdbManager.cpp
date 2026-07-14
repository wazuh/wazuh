#include <kvdbstore/kvdbManager.hpp>

#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#include <base/json.hpp>

#include <kvdbstore/kvdbHandler.hpp>

namespace kvdbstore
{

std::shared_ptr<IKVDBHandler> KVDBManager::getKVDBHandler(const cm::store::ICMStoreNSReader& nsReader,
                                                          const std::string& dbName)
{
    const auto& nsId = nsReader.getNamespaceId();

    {
        // Fast path: read lock + cache hit
        std::shared_lock<std::shared_mutex> rlk(m_mutex);
        if (auto nsIt = m_registry.find(nsId); nsIt != m_registry.end())
        {
            if (auto dbIt = nsIt->second.find(dbName); dbIt != nsIt->second.end())
            {
                if (auto alive = dbIt->second.lock())
                {
                    return std::make_shared<KVDBHandler>(std::move(alive));
                }
            }
        }
    }

    json::Json j = nsReader.getResourceByName<cm::store::dataType::KVDB>(dbName).getData();
    if (!j.isObject())
    {
        const auto nsStr = nsId.toStr();
        throw std::runtime_error("KVDB payload must be a JSON object (ns='" + nsStr + "', db='" + dbName + "').");
    }

    // Zero-copy extraction: swap member values out of j (no CopyFrom).
    // j's allocator keeps string data alive for the swapped entries.
    auto store = std::make_shared<KVMapStore>();
    store->entries = j.extractObjectMembers();
    store->sourceDoc = std::move(j); // keeps allocator alive; must outlive entries

    std::shared_ptr<const KVMapStore> cstore = std::move(store);

    {
        // Publish to cache (write lock)
        std::unique_lock<std::shared_mutex> wlk(m_mutex);
        auto& dbMap = m_registry[nsId];
        auto it = dbMap.find(dbName);
        if (it != dbMap.end())
        {
            // Another thread won: reuse theirs
            if (auto alive = it->second.lock())
            {
                cstore = std::move(alive);
            }
            else
            {
                // Refresh expired entry
                it->second = cstore;
            }
        }
        else
        {
            // First insertion
            dbMap.try_emplace(dbName, cstore);
        }
    }

    return std::make_shared<KVDBHandler>(std::move(cstore));
}

} // namespace kvdbstore
