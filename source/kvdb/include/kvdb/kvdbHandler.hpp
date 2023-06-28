#ifndef _KVDB_HANDLER_H
#define _KVDB_HANDLER_H

#include <kvdb/iKVDBHandler.hpp>

/**
 * @brief Forward Declaration of RocksDB types used here
 *
 */
namespace rocksdb
{
class DB;
class ColumnFamilyHandle;
};

namespace kvdbManager
{

class IKVDBHandlerCollection;

/**
 * @brief This is the concrete implementation of a KVDB Handler.
 */
class KVDBHandler
    : public IKVDBHandler
{
public:
    /**
     * @brief Construct a new KVDBHandler object
     *
     * @param db Pointer to the RocksDB:DB instance.
     * @param cfHandle Pointer to the RocksDB:ColumnFamilyHandle instance.
     * @param spaceName Name of the Space.
     * @param scopeName Name of the Scope.
     *
     */
    KVDBHandler(rocksdb::DB* db,
                rocksdb::ColumnFamilyHandle* cfHandle,
                std::shared_ptr<IKVDBHandlerCollection> collection,
                const std::string& spaceName,
                const std::string& scopeName);

    /**
     * @brief Destroy the KVDBHandler object
     *
     */
    ~KVDBHandler();

    /**
     * @copydoc IKVDBHandler::set(const std::string& key, const std::string& value)
     *
     */
    std::optional<base::Error> set(const std::string& key, const std::string& value) override;

    /**
     * @copydoc IKVDBHandler::set(const std::string& key, const json::Json& value)
     *
     */
    std::optional<base::Error> set(const std::string& key, const json::Json& value) override;

    /**
     * @copydoc IKVDBHandler::add
     *
     */
    std::optional<base::Error> add(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::remove
     *
     */
    std::optional<base::Error> remove(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::contains
     *
     */
    std::variant<bool, base::Error> contains(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::get
     *
     */
    std::variant<std::string, base::Error> get(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::dump
     *
     */
    std::variant<std::unordered_map<std::string, std::string>, base::Error> dump() override;

protected:
    /**
     * @brief Pointer to the RocksDB:ColumnFamilyHandle instance.
     *
     */
    rocksdb::ColumnFamilyHandle* m_pCFhandle;

    /**
     * @brief Pointer to the RocksDB:DB instance.
     *
     */
    rocksdb::DB* m_pRocksDB;

    /**
     * @brief Name of the Database. Kept reference to remove handler from collection.
     *
     */
    std::string m_dbName;

    /**
     * @brief Name of the Scope. Kept reference to remove handler from collection.
     *
     */
    std::string m_scopeName;

    /**
     * @brief Collection that synchronize handlers in Manager.
     *
     */
    std::shared_ptr<IKVDBHandlerCollection> m_spCollection;
};

} // namespace kvdbManager

#endif // _KVDB_HANDLER_H
