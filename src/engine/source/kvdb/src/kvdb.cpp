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
using ROCKSDB_NAMESPACE::Slice; /////
using ROCKSDB_NAMESPACE::Status;
using ROCKSDB_NAMESPACE::WriteBatch;
using ROCKSDB_NAMESPACE::WriteOptions;

std::string kDBExamplePath = "/tmp/rocksdb_simple_example";
std::string kDBPath = "/tmp/kvDB_wazuh_engine";

static std::vector<ColumnFamilyDescriptor> column_families = {
    // have to open default column family - FIXME: ROCKSDB_NAMESPACE::kDefaultColumnFamilyName doesn't work
    ColumnFamilyDescriptor( "default", ColumnFamilyOptions()),
    };

bool CreateKVDB() {
    DB* db;
    Options options;
    Status s;
    bool result = true;

    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();
    options.create_if_missing = true; // TODO: this should be the only method with this flag true
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
        // I need to be sure that the DB is closed before Destroying it
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

    // TODO: delete later
    DB::ListColumnFamilies(DBOptions(), kDBPath, &column_families_available);
    if(column_families_available.size() > 0) {
        for(auto familia : column_families_available)
        {
            LOG(INFO) << "[" << __func__ << "]" << " familias disponibles " << familia << std::endl;
        }
    }

    dbOptions.IncreaseParallelism();
    dbOptions.create_if_missing = true; // TODO: this should be the only method with this flag true
    dbOptions.error_if_exists = false;
    dbOptions.create_missing_column_families = true;

    for (int i = 0; i < column_families.size() ; i++ ) {
        if(!column_family_name.compare(column_families.at(i).name))
        {
            LOG(ERROR) << "[" << __func__ << "]" << " cant create a family column already present" << std::endl;
            return false;
        }
    }

    //TODO: this should remained fixed in a file or some other persistent storage
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

bool DeleteColumnFamily(std::string const column_family_name) {
    DB *db;
    Status s;
    std::vector<ColumnFamilyHandle*> handles;
    bool result = true, found = false;

    if(column_family_name.empty()) {
        LOG(ERROR) << "[" << __func__ << "]" << " can't create a family column without name " << std::endl;
        return false;
    }

    // Only available CF can be erased
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
                // Should hanlde this error
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

//TODO: delete this function and the test that use it after implementing first
//      db functions + test
void kvdb_simple_example(){
    DB* db;
    Options options;
    // Optimize RocksDB. This is the easiest way to get RocksDB to perform well
    options.IncreaseParallelism();
    options.OptimizeLevelStyleCompaction();
    // create the DB if it's not already present
    options.create_if_missing = true;

    // open DB
    Status s = DB::Open(options, kDBExamplePath, &db);
    assert(s.ok());

    // Put key-value
    s = db->Put(WriteOptions(), "key1", "value");
    assert(s.ok());
    std::string value;
    // get value
    s = db->Get(ReadOptions(), "key1", &value);
    assert(s.ok());
    assert(value == "value");

    // atomically apply a set of updates
    {
        WriteBatch batch;
        batch.Delete("key1");
        batch.Put("key2", value);
        s = db->Write(WriteOptions(), &batch);
    }

    s = db->Get(ReadOptions(), "key1", &value);
    assert(s.IsNotFound());

    db->Get(ReadOptions(), "key2", &value);
    assert(value == "value");

    {
        PinnableSlice pinnable_val;
        db->Get(ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
        assert(pinnable_val == "value");
    }

    {
        std::string string_val;
        // If it cannot pin the value, it copies the value to its internal buffer.
        // The intenral buffer could be set during construction.
        PinnableSlice pinnable_val(&string_val);
        db->Get(ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
        assert(pinnable_val == "value");
        // If the value is not pinned, the internal buffer must have the value.
        assert(pinnable_val.IsPinned() || string_val == "value");
    }

    PinnableSlice pinnable_val;
    s = db->Get(ReadOptions(), db->DefaultColumnFamily(), "key1", &pinnable_val);
    assert(s.IsNotFound());
    // Reset PinnableSlice after each use and before each reuse
    pinnable_val.Reset();
    db->Get(ReadOptions(), db->DefaultColumnFamily(), "key2", &pinnable_val);
    assert(pinnable_val == "value");
    pinnable_val.Reset();
    // The Slice pointed by pinnable_val is not valid after this point

    delete db;

}
