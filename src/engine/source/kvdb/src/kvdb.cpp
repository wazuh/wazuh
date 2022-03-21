#include "glog/logging.h"
#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/utilities/transaction.h"
#include "rocksdb/utilities/transaction_db.h"

#include <kvdb/kvdb.hpp>

using ROCKSDB_NAMESPACE::ColumnFamilyDescriptor;
using ROCKSDB_NAMESPACE::ColumnFamilyHandle;
using ROCKSDB_NAMESPACE::ColumnFamilyOptions;
using ROCKSDB_NAMESPACE::DB;
using ROCKSDB_NAMESPACE::DBOptions;
using ROCKSDB_NAMESPACE::DestroyDB;
using ROCKSDB_NAMESPACE::Options;
using ROCKSDB_NAMESPACE::PinnableSlice;
using ROCKSDB_NAMESPACE::ReadOptions;
using ROCKSDB_NAMESPACE::Slice;
using ROCKSDB_NAMESPACE::Status;
using ROCKSDB_NAMESPACE::Transaction;
using ROCKSDB_NAMESPACE::TransactionDB;
using ROCKSDB_NAMESPACE::TransactionDBOptions;
using ROCKSDB_NAMESPACE::WriteBatch;
using ROCKSDB_NAMESPACE::WriteOptions;

std::string const kKvDbPath = "/tmp/kvDB_wazuh_engine";

static std::vector<ColumnFamilyDescriptor> column_families;

/**
 * @brief Updating local arrray of CF with the ones from the DB
 *
 */
void UpdateColumnFamiliesList() {

    std::vector<std::string> pColumn_families;

    DB::ListColumnFamilies(DBOptions(), kKvDbPath, &pColumn_families);

    if(pColumn_families.size()) {
        column_families.clear();
        for(auto family : pColumn_families) {
            LOG(INFO) << "[" << __func__ << "]" << " CF name : " << family << std::endl;
            column_families.push_back(ColumnFamilyDescriptor(family,ColumnFamilyOptions()));
        }
    }
}


/**
 * @brief creation of DB on kDBPath = "/tmp/kvDB_wazuh_engine"
 *
 * @return true could create DB
 * @return false couldn't create DB
 */
bool CreateKVDB() {
    DB* db;
    Options options;
    Status s;
    bool result = true;

    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();
    options.create_if_missing = true;
    options.error_if_exists = true;

    s = DB::Open(options, kKvDbPath, &db);
    if(s.ok()) {
        s = db->Close();
        if(!s.ok()) {
            LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
        }
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
        result = false;
    }

    delete db;
    return result;
}

/**
 * @brief DB full delete including all member files
 *
 * @return true successfull delete of all DB files
 * @return false unsuccessfull delete of all DB files
 */
bool DestroyKVDB() {
    DB* db;
    Options options;
    std::vector<ColumnFamilyHandle*> handlers;
    Status s;
    bool result = true;

    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();

    UpdateColumnFamiliesList();
    s = DB::Open(DBOptions(), kKvDbPath, column_families, &handlers, &db);
    if(s.ok()) {
        // DB must be closed before destroying it
        s = db->Close();
        if(!s.ok()) {
            result = false;
            LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
        }
        else {
            DestroyDB(kKvDbPath,options);
        }
        handlers.clear();
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
        result = false;
    }

    delete db;
    return result;
}

/**
 * @brief Checks if CF is in the local array of DB and returns it's position
 *
 * @param column_family_name CF being searched
 * @return int position in vector of CFs
 */
int CFIndexInAvailableArray(std::string const &column_family_name) {
    for (int i = 0; i < column_families.size() ; i++ ) {
        if(!column_family_name.compare(column_families.at(i).name))
        {
            return i;
        }
    }
    return 0;
}

/**
 * @brief Create a Column Family object
 *
 * @param column_family_name std::string if it's no part of column_families_available
 * it will be added to it.
 * @return true successfull creation of FC in DB or FC alredy in DB
 * @return false unsuccessfull creation of FC in DB
 */
bool CreateColumnFamily(std::string const column_family_name) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handlers;
    DBOptions dbOptions;
    std::vector<std::string> column_families_available;
    bool result = true;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " cant create a family column without name " << std::endl;
        return false;
    }

    dbOptions.IncreaseParallelism();
    dbOptions.create_if_missing = true;
    dbOptions.error_if_exists = false;
    dbOptions.create_missing_column_families = true;

    UpdateColumnFamiliesList();

    if(CFIndexInAvailableArray(column_family_name)) {
        LOG(INFO) << "[" << __func__ << "]" << " cant create a family column already present" << std::endl;
        return true;
    }

    LOG(INFO) << "[" << __func__ << "]" << " Adding " << column_family_name << " as a new family column to DB " << std::endl;
    column_families.push_back(ColumnFamilyDescriptor(column_family_name, ColumnFamilyOptions()));

    s = DB::Open(dbOptions, kKvDbPath, column_families, &handlers, &db);
    if(s.ok()) {
        for (auto handle : handlers) {
            s = db->DestroyColumnFamilyHandle(handle);
            if(!s.ok()){
                LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
            }
        }
        handlers.clear();
        s = db->Close();
        if(!s.ok()) {
            result = false;
            LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
        }
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
        result = false;
    }

    delete db;
    return result;
}

/**
 * @brief Delete a Column Family object
 *
 * @param column_family_name std::string if it's part of column_families_available
 * it will be deleted from it.
 * @return true successfull deletion of FC in DB or FC alredy in DB
 * @return false unsuccessfull deletion of FC in DB
 */
bool DropColumnFamily(std::string const column_family_name) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handlers;
    bool result = true;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't delete a family column without name " << std::endl;
        return true;
    }

    UpdateColumnFamiliesList();

    int i = CFIndexInAvailableArray(column_family_name);
    if(i) {
        s = DB::Open(DBOptions(), kKvDbPath, column_families, &handlers, &db);
        if(s.ok()) {
            for(auto handle : handlers) {
                // find the correct CF handle to be erased
                if(!column_family_name.compare(handle->GetName())) {
                    s = db->DropColumnFamily(handle);
                    if(s.ok()) {
                        LOG(INFO) << "[" << __func__ << "]" << " Removing " << column_family_name << " from column_families"<< std::endl;
                        column_families.erase( column_families.begin() + i);
                    }
                    else {
                        LOG(ERROR) << "[" << __func__ << "]" << " couldn't drop CF, error: " << s.ToString() << std::endl;
                        result = false;
                    }
                }
                // destroy all the handlers prior closing
                s = db->DestroyColumnFamilyHandle(handle);
                if(!s.ok()) {
                    LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
                }
            }
            handlers.clear();

            s = db->Close();
            if(!s.ok()) {
                LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
            }

        }
        else {
            LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
            result = false;
        }

        delete db;
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " can't delete a FC that doesn't exist" << std::endl;
        result = false;
    }

    return result;
}

/**
 * @brief Avoid code duplication by making the access and search of cf more generic
 *
 * @param columnFamily where the key will be searched
 * @param value for writing purpose, reading (being modify by process), not needed in delete
 * @param key used for Writing, deleting and reading a value
 * @param action This is the action that will be executed (READ, WRITE, DELETE)
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool AccesSingleItemOfCF(std::string const &column_family_name, std::string &value,
                                                            std::string const &key, const ACTION_ON_CF action) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handlers;
    bool result = true;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a family column with no name." << std::endl;
        return false;
    }

    if(key.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a family column with no key." << std::endl;
        return false;
    }

    UpdateColumnFamiliesList();

    int i = CFIndexInAvailableArray(column_family_name);
    if(i) {
        s = DB::Open(DBOptions(), kKvDbPath, column_families, &handlers, &db);
        if(s.ok()) {

            for(auto handle : handlers) {
                // find the correct CF handle to be erased
                if(!column_family_name.compare(handle->GetName())) {
                    switch (action)
                    {
                    case ACTION_ON_CF::WRITE:
                        {
                            s = db->Put(WriteOptions(), handle, Slice(key), Slice(value));
                            if(s.ok()) {
                                LOG(INFO) << "[" << __func__ << "]" << " value insertion OK {" << key << ","
                                << value << "} into CF name : " << column_family_name << std::endl;
                            }
                            else {
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't write value into CF, error: " << s.ToString() << std::endl;
                                result = false;
                            }
                        }
                        break;

                    case ACTION_ON_CF::READ:
                        {
                            s = db->Get(ReadOptions(), handle, Slice(key), &value);
                            if(s.ok()) {
                                LOG(INFO) << "[" << __func__ << "]" << " value obtained OK {" << key << ","
                                << value << "} from CF name : " << column_family_name << std::endl;
                            }
                            else {
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't Get value from CF, error: " << s.ToString() << std::endl;
                                result = false;
                            }
                        }
                        break;

                    case ACTION_ON_CF::DELETE:
                        {
                            s = db->Delete(WriteOptions(), handle, Slice(key));
                            if(s.ok()) {
                                LOG(INFO) << "[" << __func__ << "]" << " key deleted OK {" << key << "} from CF name : " << column_family_name << std::endl;
                            }
                            else {
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't delete value from CF, error: " << s.ToString() << std::endl;
                                result = false;
                            }
                        }
                        break;

                    case ACTION_ON_CF::READ_WITHOUT_VALUE_COPY:
                        {
                            PinnableSlice pinnable_val;
                            s = db->Get(ReadOptions(), handle, Slice(key), &pinnable_val);
                            if(s.ok()) {
                                value = pinnable_val.ToString();
                                LOG(INFO) << "[" << __func__ << "]" << " value obtained OK {" << key << ","
                                << value << "} from CF name : " << column_family_name << std::endl;
                                pinnable_val.Reset();
                            }
                            else {
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into CF without copy, error: " << s.ToString() << std::endl;
                                result = false;
                            }
                        }
                        break;

                    default:
                        LOG(ERROR) << "[" << __func__ << "]" << " this case shouldn't be reacheable" << std::endl;
                        result = false;
                        break;
                    }

                }
                s = db->DestroyColumnFamilyHandle(handle);
                if(!s.ok()) {
                    LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
                }
            }
            handlers.clear();

            s = db->Close();
            if(!s.ok()) {
                LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
            }
        }
        else {
            LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
            result = false;
        }

        delete db;
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a FC that doesn't exist" << std::endl;
        result = false;
    }

    return result;
}

/**
 * @brief read a value from a key inside a CF
 *
 * @param columnFamily where to search the key
 * @param value that the result of the proccess will modify
 * @param key where to find the value
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool ReadToColumnFamily(std::string const &columnFamily, std::string const &key,
                                                            std::string &value) {

    if(AccesSingleItemOfCF(columnFamily, value, key, ACTION_ON_CF::READ)) {
        return true;
    }
    return false;
}

/**
 * @brief write a value in a key inside a CF
 *
 * @param columnFamily where to search for the key
 * @param value that will be stored inside the key
 * @param key where the value will be stored
  * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool WriteToColumnFamily(std::string const &columnFamily, std::string const &key,
                                                            std::string &value) {
    if(AccesSingleItemOfCF(columnFamily, value, key, ACTION_ON_CF::WRITE)) {
        return true;
    }
    return false;
}

/**
 * @brief delete a key of a CF
 *
 * @param columnFamily where to search for the key
 * @param value not used
 * @param key that will be deleted
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool DeleteKeyInColumnFamily(std::string const &columnFamily, std::string const &key) {
    std::string unusedValue;
    if(AccesSingleItemOfCF(columnFamily, unusedValue, key, ACTION_ON_CF::DELETE)) {
        return true;
    }
    return false;
}
/**
 * @brief read a value from a key inside a CF without value copying
 *
 * @param columnFamily where to search the key
 * @param value that the result of the proccess will modify
 * @param key where to find the value
 * @return true If the proccess finished successfully
 * @return false If the proccess didn't finished successfully
 */
bool ReadToColumnFamilyWithoutValueCopy(std::string const &columnFamily, std::string const &key,
                                                            std::string &value) {

    if(AccesSingleItemOfCF(columnFamily, value, key, ACTION_ON_CF::READ_WITHOUT_VALUE_COPY)) {
        return true;
    }
    return false;
}

bool WriteToColumnFamilyTransaction(std::string const &column_family_name,
                        std::vector<std::pair<std::string,std::string>> const pairsVector) {
    Status s;
    TransactionDBOptions txn_db_options;
    TransactionDB* txn_db;
    std::vector<ColumnFamilyHandle*> handlers;
    bool result = true;
    WriteOptions write_options;

    if(!pairsVector.size()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a Transaction without any pair." << std::endl;
        return false;
    }

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a Transaction to a family column with no name." << std::endl;
        return false;
    }

    UpdateColumnFamiliesList();

    int i = CFIndexInAvailableArray(column_family_name);
    if(i) {
        s = TransactionDB::Open(DBOptions(), txn_db_options, kKvDbPath, column_families, &handlers, &txn_db);
        if(s.ok()) {
            Transaction* txn = txn_db->BeginTransaction(write_options);
            if(txn) {
                for(auto handle : handlers) {
                    // find the correct CF handle to be erased
                    if(!column_family_name.compare(handle->GetName())) {
                        for(auto pair : pairsVector) {
                            std::string const key = pair.first;
                            std::string const value = pair.second;
                            if(key.empty()) {
                                LOG(ERROR) << "[" << __func__ << "]" << " can't write to a Transaction to a family column with no key." << std::endl;
                                return false;
                            }
                            // Write a key in this transaction
                            s = txn->Put(handle, key, value);
                            if(s.ok()) {
                                continue;
                            }
                            else {
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't execute Put in transaction -breaking loop-, error: " << s.code() << std::endl;
                                result =  false;
                            }
                        }
                        s = txn->Commit();
                        if (s.ok()) {
                            LOG(ERROR) << "[" << __func__ << "]" << " transaction commited OK" << std::endl;
                            delete txn;
                            result =  true;
                        }
                        else {
                            LOG(ERROR) << "[" << __func__ << "]" << " couldn't commit transaction, error: " << s.code() << std::endl;
                            result =  false;
                        }
                    }
                }
                handlers.clear();
            }
            else {
                LOG(ERROR) << "[" << __func__ << "]" << " couldn't begin transaction, error: " << s.code() << std::endl;
                result =  false;
            }
        }
        else {
            LOG(ERROR) << "[" << __func__ << "]" << " couldn't Open DB, error: " << s.code() << std::endl;
            result = false;
        }
        delete txn_db;
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " can't delete a FC that doesn't exist" << std::endl;
        result = false;
    }
    return result;
}

bool CleanColumnFamily(std::string const column_family_name) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handlers;
    bool result = true;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't clean a family column without name " << std::endl;
        return true;
    }

    if(DropColumnFamily(column_family_name)) {
        result = CreateColumnFamily(column_family_name);
    }

    return result;
}
