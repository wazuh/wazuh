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

#ifndef _DBENGINE_H
#define _DBENGINE_H

#include <string>
#include <vector>
#include <functional>
#include <json.hpp>
#include "typedef.h"

namespace DbSync
{
    using ResultCallback = std::function<void(ReturnTypeCallback, const nlohmann::json&)>;

    class IDbEngine
    {
    public:
        virtual void bulkInsert(const std::string& table,
                                const nlohmann::json& data) = 0;

        virtual void refreshTableData(const nlohmann::json& data,
                                      const ResultCallback callback) = 0;

        virtual void syncTableRowData(const std::string& table,
                                      const nlohmann::json& data,
                                      const ResultCallback callback) = 0;

        virtual void initializeStatusField(const std::vector<std::string>& tableNames) = 0;

        virtual void deleteRowsByStatusField(const std::vector<std::string>& tableNames) = 0;
        virtual ~IDbEngine() = default;

    protected:
        IDbEngine() = default;
    };
}// namespace DbSync

#endif // _DBENGINE_H