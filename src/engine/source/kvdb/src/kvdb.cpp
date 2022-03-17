#include "glog/logging.h" // TODO: set GLOG_minloglevel=2
#include "rocksdb/db.h"
#include "rocksdb/slice.h"
#include "rocksdb/options.h"

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
using ROCKSDB_NAMESPACE::WriteBatch;
using ROCKSDB_NAMESPACE::WriteOptions;

std::string kDBPath = "/tmp/kvDB_wazuh_engine";

static std::vector<ColumnFamilyDescriptor> column_families;

void UpdateColumnFamiliesList() {

    std::vector<std::string> pColumn_families;

    DB::ListColumnFamilies(DBOptions(), kDBPath, &pColumn_families);

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

    s = DB::Open(options, kDBPath, &db);
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
    std::vector<ColumnFamilyHandle*> handles;
    Status s;
    bool result = true;

    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();

    UpdateColumnFamiliesList();
    s = DB::Open(DBOptions(), kDBPath, column_families, &handles, &db);
    if(s.ok()) {
        // DB must be closed before destroying it
        s = db->Close();
        if(!s.ok()) {
            result = false;
            LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
        }
        else {
            DestroyDB(kDBPath,options);
        }
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
        result = false;
    }

    delete db;
    return result;
}

int CFPresent(std::string const &column_family_name) {
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
    std::vector<ColumnFamilyHandle*> handles;
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

    if(CFPresent(column_family_name)) {
        LOG(INFO) << "[" << __func__ << "]" << " cant create a family column already present" << std::endl;
        return true;
    }

    //TODO: this should remained fixed in some kind of persistent storage
    LOG(INFO) << "[" << __func__ << "]" << " Adding " << column_family_name << " as a new family column to DB " << std::endl;
    column_families.push_back(ColumnFamilyDescriptor(column_family_name, ColumnFamilyOptions()));

    s = DB::Open(dbOptions, kDBPath, column_families, &handles, &db);
    if(s.ok()) {
        for (auto handle : handles) {
            s = db->DestroyColumnFamilyHandle(handle);
            if(!s.ok()){
                LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
            }
        }

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
bool DeleteColumnFamily(std::string const column_family_name) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handles;
    bool result = true, found = false;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't delete a family column without name " << std::endl;
        return true;
    }

    UpdateColumnFamiliesList();

    int i = CFPresent(column_family_name);
    if(i) {
        found = true;
        s = DB::Open(DBOptions(), kDBPath, column_families, &handles, &db);
        if(s.ok()) {
            for(auto handle : handles) {
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
                else {
                    // destroy all the other handlers prior closing
                    s = db->DestroyColumnFamilyHandle(handle);
                    if(!s.ok()) {
                        LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
                    }
                }
            }

            // TODO: Should handle this error
            // LOG(ERROR) << "[" << __func__ << "]" << " couldn't find CF handle, error: " << s.ToString() << std::endl;
            // result = false;

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

    if(!found) {
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
    std::vector<ColumnFamilyHandle*> handles;
    bool result = true, found = false;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a family column with no name." << std::endl;
        return false;
    }

    if(key.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't write to a family column with no key." << std::endl;
        return false;
    }

    UpdateColumnFamiliesList();

    int i = CFPresent(column_family_name);
    if(i) {
        found = true;
        s = DB::Open(DBOptions(), kDBPath, column_families, &handles, &db);
        if(s.ok()) {

            for(auto handle : handles) {
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
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into CF, error: " << s.ToString() << std::endl;
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
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into CF, error: " << s.ToString() << std::endl;
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
                                LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into CF, error: " << s.ToString() << std::endl;
                                result = false;
                            }
                        }
                        break;

                    case ACTION_ON_CF::READ_VALUE_COPY:
                        {
                            // TODO: pending
                        }
                        break;

                    case ACTION_ON_CF::READ_WITHOUT_VALUE_COPY:
                        {
                            // TODO: pending
                        }
                        break;


                    default:
                        break;
                    }

                }
                // destroy all the handlers prior closing
                s = db->DestroyColumnFamilyHandle(handle);
                if(!s.ok()) {
                    LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
                }
            }

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

    if(!found) {
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
                                                            std::string const &value) {

    std::string nonConstVal = value; //TODO: avoid this or a const_cast
    if(AccesSingleItemOfCF(columnFamily, nonConstVal, key, ACTION_ON_CF::WRITE)) {
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
bool DeleteKeyInColumnFamily(std::string const &columnFamily, std::string const &key,
                                                            std::string const &value) {

    std::string nonConstVal = value; //TODO: avoid this or a const_cast
    if(AccesSingleItemOfCF(columnFamily, nonConstVal, key, ACTION_ON_CF::DELETE)) {
        return true;
    }
    return false;
}
