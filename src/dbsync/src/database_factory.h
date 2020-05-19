#pragma once
#include "sqlite_database.h"
#include "typedef.h"
#include <iostream>

class FactoryDatabase {
public:
    static std::unique_ptr<Database> Create( 
        const DatabaseType db_type, 
        const std::string& path, 
        const std::string& sql_statement) {

    if (SQLITE3 == db_type) {
      return std::make_unique<SQLiteDB>(path, sql_statement);
    }
    throw std::runtime_error("Unspecified type during factory instantiation");
  }
};