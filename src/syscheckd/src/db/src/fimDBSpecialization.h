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
#include <future>


constexpr auto FIM_FILE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"file_entry",
        "component":"fim_file",
        "index":"path",
        "checksum_field":"checksum",
        "last_event":"last_event",
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
        "last_event":"last_event",
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
        "component":"fim_registry",
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
            WindowsSpecialization::encodeString(stringToEncode);
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

template <>
class FIMDBCreator<OSType::HP_UX> final
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

template <OSType osType>
class PromiseFactory final
{
    public:
        // LCOV_EXCL_START
        static void set_value (__attribute__((unused)) std::promise<void>& promise)
        {
            throw std::runtime_error { "Invalid call for this operating system"};
        };

        static void wait (__attribute__((unused)) std::promise<void>& promise)
        {
            throw std::runtime_error { "Invalid call for this operating system"};
        };
        // LCOV_EXCL_STOP
};

template <>
class PromiseFactory<OSType::OTHERS> final
{
    public:
        static void set_value(std::promise<void>& promise) {
            promise.set_value();
        }

        static void wait(std::promise<void>& promise)
        {
            promise.get_future().wait();
        }
};

template <>
class PromiseFactory<OSType::WINDOWS> final
{
    public:
        void set_value (std::promise<void>& promise) {
            promise.set_value();
        }

        void wait (std::promise<void>& promise)
        {
            promise.get_future().wait();
        }
};

template <>
class PromiseFactory<OSType::HP_UX> final
{
    public:
        static void set_value (__attribute__((unused)) std::promise<void>& promise) {}

        static void wait (__attribute__((unused)) std::promise<void>& promise)
        {
            std::this_thread::sleep_for(std::chrono::seconds{2});
        }
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
