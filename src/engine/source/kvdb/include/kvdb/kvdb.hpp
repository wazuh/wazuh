#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <vector>

enum ACTION_ON_CF {
    WRITE = 0,
    READ,
    DELETE,
    READ_WITHOUT_VALUE_COPY,
};

bool CreateKVDB();

bool DestroyKVDB();

bool CreateColumnFamily(std::string const column_family_name);

bool DropColumnFamily(std::string const column_family_name);

bool CleanColumnFamily(std::string const column_family_name);

bool ReadToColumnFamily(std::string const &columnFamily,
    std::string const &key, std::string &value);

bool ReadToColumnFamilyWithoutValueCopy(std::string const &columnFamily,
    std::string const &key, std::string &value);

bool WriteToColumnFamily(std::string const &columnFamily,
    std::string const &key, std::string &value);

bool WriteToColumnFamilyTransaction(std::string const &column_family_name,
    std::vector<std::pair<std::string,std::string>> const pairsVector);

bool DeleteKeyInColumnFamily(std::string const &columnFamily,
    std::string const &key);

#endif // _KVDB_H
