/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "json.hpp"
#include "commonDefs.h"

namespace DbSync
{
    using ResultCallback = std::function<void(ReturnTypeCallback, const nlohmann::json&)>;

    class IDbEngine
    {
    public:
        // LCOV_EXCL_START
        virtual ~IDbEngine() = default;
        // LCOV_EXCL_STOP
    
        virtual void bulkInsert(const std::string& table,
                                const nlohmann::json& data) = 0;

        virtual void refreshTableData(const nlohmann::json& data,
                                      const ResultCallback callback) = 0;

        virtual void syncTableRowData(const std::string& table,
                                      const nlohmann::json& data,
                                      const ResultCallback callback,
                                      const bool inTransaction = false) = 0;

        virtual void setMaxRows(const std::string& table,
                                const unsigned long long maxRows) = 0;

        virtual void initializeStatusField(const nlohmann::json& tableNames) = 0;

        virtual void deleteRowsByStatusField(const nlohmann::json& tableNames) = 0;

        virtual void returnRowsMarkedForDelete(const nlohmann::json& tableNames, 
                                               const DbSync::ResultCallback callback) = 0;

        virtual void selectData(const std::string& table,
                                const nlohmann::json& query,
                                const ResultCallback& callback) = 0;

        virtual void deleteTableRowsData(const std::string& table,
                                         const nlohmann::json& jsDeletionData) = 0;

        virtual void addTableRelationship(const nlohmann::json& data) = 0;

    protected:
        IDbEngine() = default;
    };
}// namespace DbSync

#endif // _DBENGINE_H