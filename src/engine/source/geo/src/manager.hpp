#ifndef _GEO_MANAGER_HPP
#define _GEO_MANAGER_HPP

#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

#include <maxminddb.h>

#include <geo/imanager.hpp>
#include <store/istore.hpp>

#include "idownloader.hpp"

namespace geo
{

/**
 * @brief Class to hold the needed information for a database.
 */
class DbEntry
{
public:
    Type type;                         ///< The type of database.
    mutable std::shared_mutex rwMutex; ///< Read-Write mutex for thread safety access to the MMDB database.
    std::unique_ptr<MMDB_s> mmdb;      ///< The MMDB database.

    DbEntry(Type type)
        : type(type)
    {
        mmdb = std::make_unique<MMDB_s>();
    }

    DbEntry(const DbEntry&) = delete;
    DbEntry& operator=(const DbEntry&) = delete;
    DbEntry(DbEntry&&) = delete;
    DbEntry& operator=(DbEntry&&) = delete;

    ~DbEntry()
    {
        if (mmdb != nullptr)
        {
            MMDB_close(mmdb.get());
        }
    }
};

auto constexpr MAX_RETRIES = 3;
auto constexpr INTERNAL_NAME = "geo/";

class Manager final : public IManager
{
private:
    std::map<std::string, std::shared_ptr<DbEntry>> m_dbs; ///< The databases that have been added.
    std::map<Type, std::string> m_dbTypes;  ///< Map by Types for quick access to the db path. (only one db per type)
    mutable std::shared_mutex m_rwMapMutex; ///< Mutex to avoid simultaneous updates on the db map

    std::shared_ptr<store::IStoreInternal> m_store; ///< The store used to store the MMDB hash.
    std::shared_ptr<IDownloader> m_downloader;      ///< The downloader used to download the MMDB database.

public:
    virtual ~Manager() = default;

    Manager() = delete;
    Manager(const std::shared_ptr<store::IStoreInternal>& store, const std::shared_ptr<IDownloader>& downloader)
        : m_store(store)
        , m_downloader(downloader)
    {
        if (m_store == nullptr)
        {
            throw std::runtime_error("Maxmindb manager needs a non-null store");
        }

        if (m_downloader == nullptr)
        {
            throw std::runtime_error("Maxmindb manager needs a non-null downloader");
        }
    }

    base::OptError addDb(const std::string& path, Type type) override;
    base::OptError removeDb(const std::string& path) override;
    base::OptError
    remoteUpdateDb(const std::string& path, const std::string& dbUrl, const std::string& hashUrl) override;

    base::RespOrError<std::shared_ptr<ILocator>> getLocator(Type type) const override;
};

} // namespace geo
#endif // _GEO_MANAGER_HPP
