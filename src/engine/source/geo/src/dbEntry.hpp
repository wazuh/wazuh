#ifndef _GEO_DBENTRY_HPP
#define _GEO_DBENTRY_HPP

#include <memory>
#include <shared_mutex>

#include <maxminddb.h>

#include <geo/imanager.hpp>

namespace geo
{

/**
 * @brief Class to hold the needed information for a database.
 */
class DbEntry
{
public:
    std::string path;                  ///< The path to the database.
    Type type;                         ///< The type of database.
    mutable std::shared_mutex rwMutex; ///< Read-Write mutex for thread safety access to the MMDB database.
    std::unique_ptr<MMDB_s> mmdb;      ///< The MMDB database.

    DbEntry(const std::string& path, Type type)
        : path(path)
        , type(type)
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
} // namespace geo
#endif // _GEO_DBENTRY_HPP
