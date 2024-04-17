#include "manager.hpp"

#include <mutex>

#include <fmt/format.h>

#include "locator.hpp"

namespace geo
{
base::OptError Manager::addDb(const std::string& path, Type type)
{
    // Hold write lock on the map
    std::unique_lock lock(m_rwMapMutex);

    // Check if the type has already a database
    if (m_dbTypes.find(type) != m_dbTypes.end())
    {
        return base::Error {fmt::format("Type '{}' already has the database '{}'", typeName(type), m_dbTypes.at(type))};
    }

    // Check if the database is already added
    if (m_dbs.find(path) != m_dbs.end())
    {
        return base::Error {fmt::format("Database {} already added", path)};
    }

    // Add the database, checking if it exists
    auto entry = std::make_shared<DbEntry>(type);
    int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, entry->mmdb.get());
    if (MMDB_SUCCESS != status)
    {
        return base::Error {fmt::format("Cannot add database '{}': {}", path, MMDB_strerror(status))};
    }

    m_dbs.emplace(path, std::move(entry));

    return base::noError();
}

base::OptError Manager::removeDb(const std::string& path)
{
    // Hold write lock on the map
    std::unique_lock lock(m_rwMapMutex);

    // Check if the database is already added
    if (m_dbs.find(path) == m_dbs.end())
    {
        return base::Error {fmt::format("Database {} not found", path)};
    }

    {
        // Lock the database entry internal mutex for write
        std::unique_lock lockEntry(m_dbs.at(path)->rwMutex);

        // Remove the database
        m_dbs.erase(path);
    }

    // Remove the type from the map if it was the one in use
    for (auto it = m_dbTypes.begin(); it != m_dbTypes.end(); ++it)
    {
        if (it->second == path)
        {
            m_dbTypes.erase(it);
            break;
        }
    }

    return base::noError();
}

base::OptError Manager::remoteUpdateDb(const std::string& path, const std::string& dbUrl, const std::string& hashUrl)
{
    // Hold write lock on the map
    std::unique_lock lock(m_rwMapMutex);

    // Check if the database is already added
    if (m_dbs.find(path) == m_dbs.end())
    {
        return base::Error {fmt::format("Database {} not found", path)};
    }

    // Lock the database entry internal mutex for write
    std::unique_lock lockEntry(m_dbs.at(path)->rwMutex);

    try
    {
        // Query if an update is necessary
        auto internalName = base::Name(INTERNAL_NAME + path);
        auto oldHashResp = m_store->readInternalDoc(internalName);
        if (base::isError(oldHashResp))
        {
            return base::getError(oldHashResp);
        }
    }
}

base::RespOrError<std::shared_ptr<ILocator>> Manager::getLocator(Type type) const
{
    // Search the database with read lock
    std::shared_lock lock(m_rwMapMutex);

    // Check if the type has a database
    if (m_dbTypes.find(type) == m_dbTypes.end())
    {
        return base::Error {fmt::format("Type '{}' does not have a database", typeName(type))};
    }

    // Get the database entry and return the locator
    auto entry = m_dbs.at(m_dbTypes.at(type));
    auto locator = std::make_shared<Locator>(entry);

    return locator;
}

} // namespace geo
