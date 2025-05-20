#ifndef _GEO_MANAGER_HPP
#define _GEO_MANAGER_HPP

#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

#include <geo/idownloader.hpp>
#include <geo/imanager.hpp>
#include <store/istore.hpp>

namespace geo
{

/**
 * @brief Class to hold the needed information for a database.
 */
class DbEntry;

auto constexpr MAX_RETRIES = 3;
static const std::string INTERNAL_NAME = "geo";
static const std::string PATH_PATH = "/path";
static const std::string HASH_PATH = "/hash";
static const std::string TYPE_PATH = "/type";

class Manager final : public IManager
{
private:
    std::map<std::string, std::shared_ptr<DbEntry>> m_dbs; ///< The databases that have been added.
    std::map<Type, std::string> m_dbTypes;  ///< Map by Types for quick access to the db name. (only one db per type)
    mutable std::shared_mutex m_rwMapMutex; ///< Mutex to avoid simultaneous updates on the db map

    std::shared_ptr<store::IStoreInternal> m_store; ///< The store used to store the MMDB hash.
    std::shared_ptr<IDownloader> m_downloader;      ///< The downloader used to download the MMDB database.

    /**
     * @brief Upsert the internal store entry for a database.
     *
     * @param path The path to the database.
     * @return base::OptError An error if the store entry could not be upserted.
     */
    base::OptError upsertStoreEntry(const std::string& path);

    /**
     * @brief Remove the internal store entry for a database.
     *
     * @param path The path to the database.
     * @return base::OptError An error if the store entry could not be removed.
     */
    base::OptError removeInternalEntry(const std::string& path);

    /**
     * @brief Add a database to the manager without any thread safety checks.
     *
     * @param path Path to the database.
     * @param type Type of the database.
     * @param upsertStore Whether to upsert the store entry.
     * @return base::OptError An error if the database could not be added.
     */
    base::OptError addDbUnsafe(const std::string& path, Type type, bool upsertStore);

    /**
     * @brief Remove a database from the manager without any thread safety checks.
     *
     * @param path Path to the database.
     * @return base::OptError An error if the database could not be removed.
     */
    base::OptError removeDbUnsafe(const std::string& path);

    /**
     * @brief Write the MMDB database to the filesystem.
     *
     * @param path Path to store the database.
     * @param content The content of the database.
     * @return base::OptError An error if the database could not be written.
     */
    base::OptError writeDb(const std::string& path, const std::string& content);

public:
    virtual ~Manager() = default;

    Manager() = delete;
    Manager(const std::shared_ptr<store::IStoreInternal>& store, const std::shared_ptr<IDownloader>& downloader);

    /**
     * @copydoc IManager::listDbs
     */
    std::vector<DbInfo> listDbs() const override;

    /**
     * @copydoc IManager::addDb
     */
    base::OptError addDb(const std::string& path, Type type) override;

    /**
     * @copydoc IManager::removeDb
     */
    base::OptError removeDb(const std::string& path) override;

    /**
     * @copydoc IManager::remoteUpsertDb
     */
    base::OptError
    remoteUpsertDb(const std::string& path, Type type, const std::string& dbUrl, const std::string& hashUrl) override;

    /**
     * @copydoc IManager::getLocator
     */
    base::RespOrError<std::shared_ptr<ILocator>> getLocator(Type type) const override;
};

} // namespace geo
#endif // _GEO_MANAGER_HPP
