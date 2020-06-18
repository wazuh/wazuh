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
#include <string>
#include <vector>
#include "typedef.h"
#include <json.hpp>

class DbEngine 
{
public:
    virtual bool Execute(const std::string& query) = 0;
    virtual bool Select(const std::string& query, nlohmann::json& result) = 0;
    virtual bool BulkInsert(const std::string& table, const nlohmann::json& data) = 0;
    virtual bool RefreshTablaData(const nlohmann::json& data, std::tuple<nlohmann::json&, void *> delta) = 0;
    virtual ~DbEngine() = default; 
protected:
    DbEngine() = default;
};