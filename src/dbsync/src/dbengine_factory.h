/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once
#include "sqlite_dbengine.h"
#include "sqlite_wrapper_factory.h"
#include "typedef.h"
#include <iostream>

class FactoryDbEngine {
public:
    static std::unique_ptr<DbEngine> Create( 
        const DbEngineType db_type, 
        const std::string& path, 
        const std::string& sql_statement) {

    if (SQLITE3 == db_type) {
      return std::make_unique<SQLiteDBEngine>(std::make_shared<SQLiteFactory>(), path, sql_statement);
    }
    throw std::runtime_error("Unspecified type during factory instantiation");
  }
};