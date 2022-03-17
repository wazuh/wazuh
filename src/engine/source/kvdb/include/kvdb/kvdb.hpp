#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <vector>

enum ACTION_ON_CF {
    WRITE = 0,
    READ,
    DELETE,
    READ_VALUE_COPY,
    READ_WITHOUT_VALUE_COPY,
};

bool CreateKVDB();

bool DestroyKVDB();

bool CreateColumnFamily(std::string const column_family_name);

bool DeleteColumnFamily(std::string const column_family_name);

bool ReadToColumnFamily(std::string const &columnFamily,
    std::string const &key, std::string &value);

bool WriteToColumnFamily(std::string const &columnFamily,
    std::string const &key, std::string const &value);

bool DeleteKeyInColumnFamily(std::string const &columnFamily,
    std::string const &key, std::string const &value = std::string());

#endif // _KVDB_H
