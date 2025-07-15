/*
 * Wazuh Syscheck
 * Copyright (C) 2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_OS_SPECIALIZATION_H
#define _FIMDB_OS_SPECIALIZATION_H

#include "fimDB.hpp"
#include "fimCommonDefs.h"
#include "encodingWindowsHelper.h"
#include "fimDBSpecializationWindows.hpp"

static auto fileSyncConfig
{
    RegisterConfiguration::builder().decoderType("JSON_RANGE")
    .table("file_entry")
    .component("fim_file")
    .index("path")
    .checksumField("checksum")
    .lastEvent("last_event")
    .noData(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
    .countRange(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .countFieldName("count")
            .columnList({"count(*) AS count"})
            .distinctOpt(false)
            .orderByOpt(""))
    .rowData(QueryParameter::builder().rowFilter("WHERE path = '?'")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
    .rangeChecksum(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
};

static auto registryKeySyncConfig
{
    RegisterConfiguration::builder().decoderType("JSON_RANGE")
    .table("registry_key")
    .component("fim_registry_key")
    .index("path")
    .checksumField("checksum")
    .lastEvent("last_event")
    .noData(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
    .countRange(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .countFieldName("count")
            .columnList({"count(*) AS count"})
            .distinctOpt(false)
            .orderByOpt(""))
    .rowData(QueryParameter::builder().rowFilter("WHERE path = '?'")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
    .rangeChecksum(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
};

static auto registryValueSyncConfig
{
    RegisterConfiguration::builder().decoderType("JSON_RANGE")
    .table("registry_data")
    .component("fim_registry_value")
    .index("path")
    .checksumField("checksum")
    .lastEvent("last_event")
    .noData(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
    .countRange(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .countFieldName("count")
            .columnList({"count(*) AS count"})
            .distinctOpt(false)
            .orderByOpt(""))
    .rowData(QueryParameter::builder().rowFilter("WHERE path = '?'")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
    .rangeChecksum(QueryParameter::builder().rowFilter("WHERE path BETWEEN '?' and '?' ORDER BY path")
            .columnList({"*"})
            .distinctOpt(false)
            .orderByOpt(""))
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
    R"({"table":"registry_key",
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
        "component":"fim_registry_key",
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
constexpr auto FIM_VALUE_START_CONFIG_STATEMENT
{
    R"({"table":"registry_data",
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
        "component":"fim_registry_value",
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
        static void setLimits(__attribute__((unused)) std::shared_ptr<DBSync> DBSyncHandler,
                              __attribute__((unused)) const unsigned int& fileLimit,
                              __attribute__((unused)) const unsigned int& registryLimit)
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

        static void registerRsync(__attribute__((unused)) std::shared_ptr<RemoteSync> RSyncHandler,
                                  __attribute__((unused)) const RSYNC_HANDLE& handle,
                                  __attribute__((unused)) std::function<void(const std::string&)> syncFileMessageFunction,
                                  __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction,
                                  __attribute__((unused)) const bool syncRegistryEnabled)
        {
            throw std::runtime_error
            {
                "Error registering synchronization."
            };
        }

        static void sync(__attribute__((unused)) std::shared_ptr<RemoteSync> RSyncHandler,
                         __attribute__((unused)) const DBSYNC_HANDLE& handle,
                         __attribute__((unused)) std::function<void(const std::string&)> syncFileMessageFunction,
                         __attribute__((unused)) std::function<void(const std::string&)> syncRegistryMessageFunction)
        {
            throw std::runtime_error
            {
                "Error running synchronization."
            };
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode)
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
                              const int fileLimit,
                              const int registryLimit)
        {
            DBSyncHandler->setTableMaxRow("file_entry", fileLimit);
            DBSyncHandler->setTableMaxRow("registry_key", registryLimit);
            DBSyncHandler->setTableMaxRow("registry_data", registryLimit);

        }

        static std::string CreateStatement()
        {
            std::string ret { CREATE_FILE_DB_STATEMENT };
            ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
            ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;

            return ret;
        }

        static void registerRsync(std::shared_ptr<RemoteSync> RSyncHandler,
                                  const RSYNC_HANDLE& handle,
                                  std::function<void(const std::string&)> syncFileMessageFunction,
                                  std::function<void(const std::string&)> syncRegistryMessageFunction,
                                  const bool syncRegistryEnabled)
        {
            RSyncHandler->registerSyncID(FIM_COMPONENT_FILE,
                                        handle,
                                        fileSyncConfig.config(),
                                        syncFileMessageFunction);

            if (syncRegistryEnabled)
            {
                RSyncHandler->registerSyncID(FIM_COMPONENT_REGISTRY_KEY,
                                            handle,
                                            registryKeySyncConfig.config(),
                                            syncRegistryMessageFunction);

                RSyncHandler->registerSyncID(FIM_COMPONENT_REGISTRY_VALUE,
                                            handle,
                                            registryValueSyncConfig.config(),
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
                RSyncHandler->startSync(handle,
                                        nlohmann::json::parse(FIM_VALUE_START_CONFIG_STATEMENT),
                                        syncRegistryMessageFunction);
            }
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode)
        {
            WindowsSpecialization::encodeString(stringToEncode);
        }
};

template <>
class FIMDBCreator<OSType::OTHERS> final
{
    public:
        static void setLimits(std::shared_ptr<DBSync> DBSyncHandler,
                              const int fileLimit,
                              __attribute__((unused)) const int registryLimit)
        {
            DBSyncHandler->setTableMaxRow("file_entry", fileLimit);
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
                                        fileSyncConfig.config(),
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

template <OSType osType>
class RegistryTypes final
{
    public:
        // LCOV_EXCL_START
        static const std::string typeText(__attribute__((unused))const int32_t type)
        {
            throw std::runtime_error { "Invalid call for this operating system"};
        };
        // LCOV_EXCL_STOP
};
template <>
class RegistryTypes<OSType::WINDOWS> final
{
    public:
        static const std::string typeText(const int32_t type)
        {
            return WindowsSpecialization::registryTypeToText(type);
        };
};

#endif // _FIMDB_OS_SPECIALIZATION_H
