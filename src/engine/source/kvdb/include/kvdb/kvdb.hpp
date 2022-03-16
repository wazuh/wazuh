#ifndef _KVDB_H
#define _KVDB_H

#include <string>
#include <vector>

bool CreateKVDB();

bool DestroyKVDB();

bool CreateColumnFamily(std::string const column_family_name);

bool DeleteColumnFamily(std::string const column_family_name);

#endif // _KVDB_H
