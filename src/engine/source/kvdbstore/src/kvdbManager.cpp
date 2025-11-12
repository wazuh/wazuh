#include <kvdb/kvdbManager.hpp>

#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <utility>
#include <vector>

#include <base/json.hpp>

#include <kvdb/kvdbHandler.hpp>

namespace kvdbStore
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

    const json::Json j = nsReader.getResourceByName<cm::store::dataType::KVDB>(dbName).getData();
    auto members = j.getObject("");
    if (!members)
    {
        const auto nsStr = nsId.toStr();
        throw std::runtime_error("KVDB payload must be a JSON object (ns='" + nsStr + "', db='" + dbName + "').");
    }

    auto wmap = std::make_shared<KVMap>();
    wmap->reserve(members->size());

    for (auto& [k, v] : *members)
    {
        wmap->try_emplace(std::move(k), std::move(v));
    }

    std::shared_ptr<const KVMap> cmap = std::move(wmap);

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
                cmap = std::move(alive);
            }
            else
            {
                // Refresh expired entry
                it->second = cmap;
            }
        }
        else
        {
            // First insertion
            dbMap.try_emplace(dbName, cmap);
        }
    }

    return std::make_shared<KVDBHandler>(std::move(cmap));
}

} // namespace kvdbStore
