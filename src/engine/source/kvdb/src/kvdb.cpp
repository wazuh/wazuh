#include <assert.h>
#include <iostream>

#include "glog/logging.h"
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

static std::vector<ColumnFamilyDescriptor> column_families = {
    //TODO: ROCKSDB_NAMESPACE::kDefaultColumnFamilyName produces an error
    ColumnFamilyDescriptor( "default", ColumnFamilyOptions()),
    };

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

/**
 * @brief Create a Column Family object
 *
 * @param column_family_name std::string if it's no part of column_families_available
 * it will be added to it.
 * @return true successfull creation of FC in DB
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

    for (int i = 0; i < column_families.size() ; i++ ) {
        if(!column_family_name.compare(column_families.at(i).name))
        {
            LOG(ERROR) << "[" << __func__ << "]" << " cant create a family column already present" << std::endl;
            return false;
        }
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
 * @return true successfull deletion of FC in DB
 * @return false unsuccessfull deletion of FC in DB
 */
bool DeleteColumnFamily(std::string const column_family_name) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handles;
    bool result = true, found = false;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't create a family column without name " << std::endl;
        return false;
    }

    for (int i = 0; i < column_families.size() ; i++ ) {
        if(!column_family_name.compare(column_families.at(i).name)) {
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
                    // destroy all the handlers prior closing
                    s = db->DestroyColumnFamilyHandle(handle);
                    if(!s.ok()) {
                        LOG(WARNING) << "[" << __func__ << "]" << " couldn't delete column family handler, error: " << s.ToString() << std::endl;
                    }
                }
                // TODO: Should handle this error
                // LOG(ERROR) << "[" << __func__ << "]" << " couldn't find CF handle, error: " << s.ToString() << std::endl;
                // result = false;
            }
            else {
                LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file, error: " << s.ToString() << std::endl;
                result = false;
            }

            s = db->Close();
            if(!s.ok()) {
                LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file, error: " << s.ToString() << std::endl;
            }
            delete db;
        }
    }

    if(!found) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't delete a FC that doesn't exist" << std::endl;
        result = false;
    }

    return result;
}
