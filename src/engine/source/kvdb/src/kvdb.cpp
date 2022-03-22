#include <assert.h>
#include <iostream>
#include <unordered_map>

#include "rocksdb/db.h"
#include "rocksdb/options.h"
#include "rocksdb/slice.h"
#include "rocksdb/utilities/transaction.h"
#include "rocksdb/utilities/transaction_db.h"

#include "kvdb.hpp"

KVDB::KVDB(const std::string& DBName, const std::string& path) {
    auto DBPath = path + DBName;

    name = DBName;
    ROCKSDB::Status s;
    std::vector<std::string> CFNames;
    s = ROCKSDB::DB::ListColumnFamilies(options.open, DBPath, &CFNames);
    if (s.ok()) {
        for (auto CFName : CFNames) {
            CFDescriptors.push_back(ROCKSDB::ColumnFamilyDescriptor(CFName, options.CF));
        }
        s = ROCKSDB::DB::Open(options.open, DBPath, CFDescriptors, &CFHandles, &db);
        if(s.ok()) {
            for (auto CFHandle : CFHandles) {
                CFHandlesMap[CFHandle->GetName()] = CFHandle;
            }
            state = State::Open;
        }
        else {
            // Log
            state = State::Error;
        }
    }
    else{
        // Log
        state = State::Error;
    }
}

bool KVDB::write(const std::string& key, const std::string& value, const std::string& columnName) {
    CFHMap::const_iterator cfh = CFHandlesMap.find(columnName);
    if (cfh == CFHandlesMap.end()) {
        // LOG Invalid CF
        return false;
    }

    ROCKSDB::Status s = db->Put(options.write, cfh->second, ROCKSDB::Slice(key), ROCKSDB::Slice(value));
    if(!s.ok()) {
        //LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into CF, error: " << s.ToString() << std::endl;
        return false;
    }

    //LOG(DEBUG) << "[" << __func__ << "]" << " value insertion OK {" << key << ","
    //<< value << "} into CF name : " << columnFamily << std::endl;
    return true;
}

#if 0
std::string KVDB::Read(const std::string& key, const std::string& ColumnName){
    //Get CF handle
    s = db->Get(ReadOptions(), handle, Slice(key), &value);
    if(s.ok()) {
        LOG(INFO) << "[" << __func__ << "]" << " value obtained OK {" << key << ","
        << value << "} from CF name : " << columnFamily << std::endl;
    }
    else {
        LOG(ERROR) << "[" << __func__ << "]" << " couldn't insert value into CF, error: " << s.ToString() << std::endl;
        result = false;
    }
}
#endif
