/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _FIMDB_OS_SPECIALIZATION_H
#define _FIMDB_OS_SPECIALIZATION_H

#include "fimDB.hpp"
#include "fimCommonDefs.h"
#include "encodingWindowsHelper.h"


constexpr auto FIM_FILE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"file_entry",
        "component":"fim_file",
        "index":"path",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE path ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto FIM_REGISTRY_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"registry_view",
        "component":"fim_registry",
        "index":"path",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE path ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

/* Statement related to files items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_FILE_START_CONFIG_STATEMENT
{
    R"({"table":"file_entry",
        "first_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path ASC",
                "count_opt":1
            },
        "component":"fim_file",
        "index":"path",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["path, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

/* Statement related to registries items. Defines everything necessary to perform the synchronization loop */
constexpr auto FIM_REGISTRY_START_CONFIG_STATEMENT
{
    R"({"table":"registry_view",
        "first_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["path"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"path ASC",
                "count_opt":1
            },
        "component":"syscheck",
        "index":"path",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE path BETWEEN '?' and '?' ORDER BY path",
                "column_list":["path, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};

template <OSType osType>
class FIMDBCreator final
{
    public:
        static void setLimits(std::shared_ptr<DBSync> DBSyncHandler,
                              const unsigned int& fileLimit,
                              const unsigned int& registryLimit)
        {
            throw std::runtime_error
            {
                "Error setting limits."
            };
        }

        static std::string CreateStatement()
        {
            throw std::runtime_error
            {
                "Error creating FIMDB statement."
            };
        }

        static void registerRsync(std::shared_ptr<RemoteSync> RSyncHandler,
                                  const RSYNC_HANDLE& handle,
                                  std::function<void(const std::string&)> syncFileMessageFunction,
                                  __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction,
                                  const bool syncRegistryEnabled)
        {
            throw std::runtime_error
            {
                "Error registering synchronization."
            };
        }

        static void sync(std::shared_ptr<RemoteSync> RSyncHandler,
                         const DBSYNC_HANDLE& handle,
                         std::function<void(const std::string&)> syncFileMessageFunction,
                         __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction)
        {
            throw std::runtime_error
            {
                "Error running synchronization."
            };
        }

        static void encodeString(std::string& stringToEncode)
        {
            throw std::runtime_error
            {
                "Error encoding strings."
            };
        }
};

template <>
class FIMDBCreator<OSType::WINDOWS> final
{
    public:
        static void setLimits(std::shared_ptr<DBSync> DBSyncHandler,
                              const unsigned int& fileLimit,
                              const unsigned int& registryLimit)
        {
            if (fileLimit > 0)
            {
                DBSyncHandler->setTableMaxRow("file_entry", fileLimit);

            }
            if (registryLimit > 0)
            {
                DBSyncHandler->setTableMaxRow("registry_key", registryLimit);
                DBSyncHandler->setTableMaxRow("registry_data", registryLimit);
            }

        }

        static std::string CreateStatement()
        {
            std::string ret { CREATE_FILE_DB_STATEMENT };
            ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
            ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
            ret += CREATE_REGISTRY_VIEW_STATEMENT;

            return ret;
        }

        static void registerRsync(std::shared_ptr<RemoteSync> RSyncHandler,
                                  const RSYNC_HANDLE& handle,
                                  std::function<void(const std::string&)> syncFileMessageFunction,
                                  __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction,
                                  const bool syncRegistryEnabled)
        {
            RSyncHandler->registerSyncID(FIM_COMPONENT_FILE,
                                        handle,
                                        nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT),
                                        syncFileMessageFunction);

            if (syncRegistryEnabled)
            {

                RSyncHandler->registerSyncID(FIM_COMPONENT_REGISTRY,
                                            handle,
                                            nlohmann::json::parse(FIM_REGISTRY_SYNC_CONFIG_STATEMENT),
                                            syncRegistryMessageFunction);
            }

        }

        static void sync(std::shared_ptr<RemoteSync> RSyncHandler,
                         const DBSYNC_HANDLE& handle,
                         std::function<void(const std::string&)> syncFileMessageFunction,
                         __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction,
                         const bool syncRegistryEnabled)
        {
            RSyncHandler->startSync(handle,
                                    nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT),
                                    syncFileMessageFunction);

            if (syncRegistryEnabled)
            {
                RSyncHandler->startSync(handle,
                                        nlohmann::json::parse(FIM_REGISTRY_START_CONFIG_STATEMENT),
                                        syncRegistryMessageFunction);
            }
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode)
        {
#ifdef WIN32
            stringToEncode = Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(stringToEncode);
#endif
        }
};

template <>
class FIMDBCreator<OSType::OTHERS> final
{
    public:
        static void setLimits(std::shared_ptr<DBSync> DBSyncHandler,
                              const unsigned int& fileLimit,
                              __attribute__((unused)) const unsigned int& registryLimit)
        {
            if (fileLimit > 0)
            {
                DBSyncHandler->setTableMaxRow("file_entry", fileLimit);
            }
        }

        static std::string CreateStatement()
        {
            return CREATE_FILE_DB_STATEMENT;
        }

        static void registerRsync(std::shared_ptr<RemoteSync> RSyncHandler,
                                  const RSYNC_HANDLE& handle,
                                  std::function<void(const std::string&)> syncFileMessageFunction,
                                  __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction,
                                  __attribute__((unused)) const bool syncRegistryEnabled)
        {
            RSyncHandler->registerSyncID(FIM_COMPONENT_FILE,
                                        handle,
                                        nlohmann::json::parse(FIM_FILE_SYNC_CONFIG_STATEMENT),
                                        syncFileMessageFunction);
        }

        static void sync(std::shared_ptr<RemoteSync> RSyncHandler,
                         const DBSYNC_HANDLE& handle,
                         std::function<void(const std::string&)> syncFileMessageFunction,
                         __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction,
                         __attribute__((unused)) const bool syncRegistryEnabled)
        {
            RSyncHandler->startSync(handle,
                                    nlohmann::json::parse(FIM_FILE_START_CONFIG_STATEMENT),
                                    syncFileMessageFunction);
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode){}
};

#endif // _FIMDB_OS_SPECIALIZATION_H
