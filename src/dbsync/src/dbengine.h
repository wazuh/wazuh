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

namespace DbSync
{
    class IDbEngine
    {
    public:
        virtual void execute(const std::string& query) = 0;
        virtual void select(const std::string& query,
                            nlohmann::json& result) = 0;
        virtual void bulkInsert(const std::string& table,
                                const nlohmann::json& data) = 0;
        virtual void refreshTableData(const nlohmann::json& data,
                                      std::tuple<nlohmann::json&, void *> delta) = 0;
        virtual ~IDbEngine() = default;
    protected:
        IDbEngine() = default;
    };
}// namespace DbSync