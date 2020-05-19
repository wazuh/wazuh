#pragma once
#include <string>
#include <vector>
#include "typedef.h"
#include <json.hpp>

class Database 
{
public:
    virtual bool Execute(const std::string& query) = 0;
    virtual bool Select(const std::string& query, std::vector<std::string>& result) = 0;
    virtual bool BulkInsert(const nlohmann::json& data) = 0;
    virtual ~Database() = default;
protected:
    Database() = default;
};