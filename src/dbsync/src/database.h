#pragma once
#include <string>
#include <vector>
#include "typedef.h"
#include <json.hpp>

class Database 
{
public:
    virtual bool Execute(const std::string& query) = 0;
    virtual bool Select(const std::string& query, nlohmann::json& result) = 0;
    virtual bool BulkInsert(const std::string& table, const nlohmann::json& data) = 0;
    virtual bool RefreshTablaData(const nlohmann::json& data, nlohmann::json& delta) = 0;
    virtual ~Database() = default;
protected:
    Database() = default;
};