/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBENGINE_H
#define _DBENGINE_H

#include <set>
#include <string>
#include <vector>
#include <functional>
#include <shared_mutex>
#include "json.hpp"
#include "commonDefs.h"
#include "abstractLocking.hpp"

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
                                          const ResultCallback callback,
                                          std::unique_lock<std::shared_timed_mutex>& lock) = 0;

            virtual void syncTableRowData(const nlohmann::json& jsInput,
                                          const ResultCallback callback,
                                          const bool inTransaction,
                                          Utils::ILocking& mutex) = 0;

            virtual void setMaxRows(const std::string& table,
                                    const int64_t maxRows) = 0;

            virtual void initializeStatusField(const nlohmann::json& tableNames) = 0;

            virtual void deleteRowsByStatusField(const nlohmann::json& tableNames) = 0;

            virtual void returnRowsMarkedForDelete(const nlohmann::json& tableNames,
                                                   const DbSync::ResultCallback callback,
                                                   std::unique_lock<std::shared_timed_mutex>& lock) = 0;

            virtual void selectData(const std::string& table,
                                    const nlohmann::json& query,
                                    const ResultCallback& callback,
                                    std::unique_lock<std::shared_timed_mutex>& lock) = 0;

            virtual void deleteTableRowsData(const std::string& table,
                                             const nlohmann::json& jsDeletionData) = 0;

            virtual void addTableRelationship(const nlohmann::json& data) = 0;

        protected:
            IDbEngine() = default;
    };
}// namespace DbSync

#endif // _DBENGINE_H
