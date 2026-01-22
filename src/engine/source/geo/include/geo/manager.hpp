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
class DbHandle;

auto constexpr MAX_RETRIES = 3;
static const std::string INTERNAL_NAME = "geo";
static const std::string PATH_PATH = "/path";
static const std::string HASH_PATH = "/hash";
static const std::string TYPE_PATH = "/type";
static const std::string CREATED_AT_PATH = "/created_at";

class Manager final : public IManager
{
private:
    std::map<std::string, std::shared_ptr<DbHandle>> m_dbs; ///< The databases that have been added.
    std::map<Type, std::string> m_dbTypes;  ///< Map by Types for quick access to the db name. (only one db per type)
    mutable std::shared_mutex m_rwMapMutex; ///< Mutex to avoid simultaneous updates on the db map

    std::shared_ptr<store::IStore> m_store; ///< The store used to store the MMDB hash.
    std::shared_ptr<IDownloader> m_downloader;      ///< The downloader used to download the MMDB database.

    /**
     * @brief Upsert the internal store entry for a local database (computes hash from file).
     *
     * @param path The path to the database.
     * @param type The type of the database.
     * @param hash The hash of the database.
     * @param createdAt The creation timestamp of the database.
     * @return base::OptError An error if the store entry could not be upserted.
     */
    base::OptError
    upsertStoreEntry(const std::string& path, Type type, const std::string& hash, const std::string& createdAt);

    /**
     * @brief Check if a database needs to be updated by comparing stored hash with remote hash.
     *
     * @param name The name of the database.
     * @param remoteHash The remote hash to compare against.
     * @return bool True if the database needs to be updated, false otherwise.
     */
    bool needsUpdate(const std::string& name, const std::string& remoteHash) const;

    /**
     * @brief Add a database to the manager without any thread safety checks.
     *
     * @param path Path to the database.
     * @param hash Hash of the database.
     * @param createdAt Creation timestamp of the database.
     * @param type Type of the database.
     * @return base::OptError An error if the database could not be added.
     */
    base::OptError
    addDbUnsafe(const std::string& path, const std::string& hash, const std::string& createdAt, Type type);

    /**
     * @brief Write the MMDB database to the filesystem.
     *
     * @param path Path to store the database.
     * @param content The content of the database.
     * @return base::OptError An error if the database could not be written.
     */
    base::OptError writeDb(const std::string& path, const std::string& content);

    /**
     * @brief Process a single database type from the manifest (download, validate, extract, load).
     *
     * @param path Path to store the database.
     * @param type Type of the database.
     * @param tarGzUrl URL to download the tar.gz database.
     * @param expectedMd5 Expected MD5 hash of the tar.gz file.
     * @param createdAt Creation timestamp from manifest.
     * @return base::OptError An error if the database could not be processed.
     */
    base::OptError processDbEntry(const std::string& path,
                                  Type type,
                                  const std::string& tarGzUrl,
                                  const std::string& expectedMd5,
                                  const std::string& createdAt);

public:
    virtual ~Manager() = default;

    Manager() = delete;
    Manager(const std::shared_ptr<store::IStore>& store, const std::shared_ptr<IDownloader>& downloader);

    /**
     * @copydoc IManager::listDbs
     */
    std::vector<DbInfo> listDbs() const override;

    /**
     * @copydoc IManager::remoteUpsert
     */
    void remoteUpsert(const std::string& manifestUrl, const std::string& cityPath, const std::string& asnPath) override;

    /**
     * @copydoc IManager::getLocator
     */
    base::RespOrError<std::shared_ptr<ILocator>> getLocator(Type type) const override;
};

} // namespace geo
#endif // _GEO_MANAGER_HPP
