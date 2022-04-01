#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <unordered_map>
#include <vector>

#include "rocksdb/db.h"
#include "rocksdb/utilities/transaction_db.h"

class KVDB
{
public:
    KVDB(const std::string &dbName, const std::string &folder);
    KVDB() = default;
    KVDB(KVDB const &) = delete;
    void operator=(KVDB const &) = delete;
    ~KVDB();

    const std::string &getName() const
    {
        return m_name;
    }

    enum class State
    {
        Closed,
        Open,
        Locked,
        Error,
        Invalid,
    };

    const State getState() const
    {
        return m_state;
    }

    bool isReady();

    bool createColumn(const std::string &columnName);

    // TODO: all the default column names should be changed, one option is to
    // define a KVDB default CF in order to avoid using a deleteColumn or
    // cleanColumn without any argument
    bool deleteColumn(const std::string &columnName = DEFAULT_CF_NAME);

    bool cleanColumn(const std::string &columnName = DEFAULT_CF_NAME);

    bool write(const std::string &key,
               const std::string &value,
               const std::string &columnName = DEFAULT_CF_NAME);

    bool writeToTransaction(
        const std::vector<std::pair<std::string, std::string>>& pairsVector,
        const std::string &columnName = DEFAULT_CF_NAME);

    bool hasKey(const std::string &key,
                const std::string &columnName = DEFAULT_CF_NAME);

    std::string read(const std::string &key,
                     const std::string &columnName = DEFAULT_CF_NAME);

    bool readPinned(const std::string &key,
                    std::string &val,
                    const std::string &columnName = DEFAULT_CF_NAME);

    bool deleteKey(const std::string &key,
                   const std::string &columnName = DEFAULT_CF_NAME);
    bool close();
    bool destroy();

    constexpr static const char* DEFAULT_CF_NAME {"default"};

private:
    std::string m_name = "Invalid";
    std::string m_path;
    State m_state = State::Invalid;

    rocksdb::DB *m_db;
    rocksdb::TransactionDB *m_txndb;
    std::vector<rocksdb::ColumnFamilyDescriptor> CFDescriptors;
    using CFHMap =
        std::unordered_map<std::string, rocksdb::ColumnFamilyHandle *>;
    CFHMap m_CFHandlesMap;
};

#endif // _KVDB_H
