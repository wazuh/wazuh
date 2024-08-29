#ifndef _KVDB_HANDLER_H
#define _KVDB_HANDLER_H

#include <kvdb/ikvdbhandler.hpp>
#include <kvdb/ikvdbhandlercollection.hpp>

#include <rocksdb/slice.h>

/**
 * @brief Forward Declaration of RocksDB types used here
 *
 */
namespace rocksdb
{
class DB;
class ColumnFamilyHandle;
}; // namespace rocksdb

namespace kvdbManager
{

class IKVDBHandlerCollection;

/**
 * @brief This is the concrete implementation of a KVDB Handler.
 */
class KVDBHandler : public IKVDBHandler
{
public:
    /**
     * @brief Construct a new KVDBHandler object
     *
     * @param db Pointer to the RocksDB:DB instance.
     * @param cfHandle Pointer to the RocksDB:ColumnFamilyHandle instance.
     * @param dbName Name of the DB.
     * @param scopeName Name of the Scope.
     *
     */
    KVDBHandler(std::weak_ptr<rocksdb::DB> weakDB,
                std::weak_ptr<rocksdb::ColumnFamilyHandle> weakCFHandle,
                std::shared_ptr<IKVDBHandlerCollection> collection,
                const std::string& dbName,
                const std::string& scopeName)
        : m_weakDB {weakDB}
        , m_weakCFHandle {weakCFHandle}
        , m_dbName {dbName}
        , m_scopeName {scopeName}
        , m_spCollection {collection}
    {
    }

    /**
     * @brief Destroy the KVDBHandler object
     *
     */
    ~KVDBHandler();

    /**
     * @copydoc IKVDBHandler::set(const std::string& key, const std::string& value)
     *
     */
    base::OptError set(const std::string& key, const std::string& value) override;

    /**
     * @copydoc IKVDBHandler::set(const std::string& key, const json::Json& value)
     *
     */
    base::OptError set(const std::string& key, const json::Json& value) override;

    /**
     * @copydoc IKVDBHandler::add
     *
     */
    base::OptError add(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::remove
     *
     */
    base::OptError remove(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::contains
     *
     */
    base::RespOrError<bool> contains(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::get
     *
     */
    base::RespOrError<std::string> get(const std::string& key) override;

    /**
     * @copydoc IKVDBHandler::dump
     *
     */
    base::RespOrError<std::list<std::pair<std::string, std::string>>> dump(const unsigned int page,
                                                                           const unsigned int records) override;

    /**
     * @copydoc IKVDBHandler::search
     *
     */
    base::RespOrError<std::list<std::pair<std::string, std::string>>>
    search(const std::string& filter, const unsigned int page, const unsigned int records) override;

protected:
    /**
     *  @brief Weak Pointer to the RocksDB:ColumnFamilyHandle instance.
     *
     */
    std::weak_ptr<rocksdb::ColumnFamilyHandle> m_weakCFHandle;

    /**
     * @brief Weak Pointer to the RocksDB:DB instance.
     *
     */
    std::weak_ptr<rocksdb::DB> m_weakDB;

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

private:
    /**
     * @brief Function to page the content of iterator
     *
     * @param page
     * @param records
     * @param filter
     * @return base::RespOrError<std::list<std::pair<std::string, std::string>>>, base::Error>
     */
    base::RespOrError<std::list<std::pair<std::string, std::string>>> pageContent(
        const unsigned int page, const unsigned int records, const std::function<bool(const rocksdb::Slice&)>& filter);

    /**
     * @brief Function to page the content of iterator
     *
     * @param page
     * @param records
     * @return base::RespOrError<std::list<std::pair<std::string, std::string>>>, base::Error>
     */
    base::RespOrError<std::list<std::pair<std::string, std::string>>> pageContent(const unsigned int page,
                                                                                  const unsigned int records);
};

} // namespace kvdbManager

#endif // _KVDB_HANDLER_H
