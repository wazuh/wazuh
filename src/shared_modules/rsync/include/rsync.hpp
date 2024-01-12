/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * October 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSYNC_HPP_
#define _RSYNC_HPP_

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <functional>
#include <thread>
#include "json.hpp"
#include "commonDefs.h"
#include "builder.hpp"

using SyncCallbackData = const std::function<void(const std::string&)>;

constexpr auto RSYNC_LOG_TAG { "rsync" };

class EXPORTED RemoteSync
{
    public:
        /**
        * @brief Initializes the shared library.
        *
        * @param logFunction Pointer to log function to be used by the rsync.
        */
        static void initialize(std::function<void(const std::string&)> logFunction);

        /**
         * @brief Method to initialize the shared library with a full log function.
         *
         * @param logFunction Log function.
         */
        static void initializeFullLogFunction(const std::function<void(const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>& logFunction);

        /**
         * @brief Remote sync initializes the instance.
         *
         * @param threadPoolSize Size of the thread pool.
         * @param maxQueueSize Maximum size of the queue.
         */
        RemoteSync(const unsigned int threadPoolSize = std::thread::hardware_concurrency(), const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE);

        /**
         * @brief RSync Constructor.
         *
         * @param handle Handle to point another rsync instance.
         *
         */
        RemoteSync(RSYNC_HANDLE handle);
        // LCOV_EXCL_START
        virtual ~RemoteSync();
        // LCOV_EXCL_STOP

        /**
         * @brief Turns off the services provided by the shared library.
         */
        static void teardown();

        /**
         * @brief Initializes the \p handle instance.
         * @param dbsyncHandle       DBSync handle to synchronize databases.
         * @param startConfiguration Statement used as a synchronization start.
         * @param callbackData       This callback is used to send sync information.
         *
         */
        virtual void startSync(const DBSYNC_HANDLE   dbsyncHandle,
                               const nlohmann::json& startConfiguration,
                               SyncCallbackData      callbackData);

        /**
         * @brief Establishes a message-id to be processed in the agent-manager sync.
         *
         * @param messageHeaderID    Message ID associated to procees messages between
         *                           agent and manager.
         * @param dbsyncHandle       DBSync handle to synchronize databases.
         * @param syncConfiguration  Statement used as a configuration.
         * @param callbackData       This callback is used to send sync information.
         *
         */
        virtual void registerSyncID(const std::string&    messageHeaderID,
                                    const DBSYNC_HANDLE   dbsyncHandle,
                                    const nlohmann::json& syncConfiguration,
                                    SyncCallbackData      callbackData);
        /**
         * @brief Pushes the \p payload message within a queue to process it in an async
         *  dispatch queue.
         *
         * @param payload Message to be queued and processed.
         *
         */
        virtual void pushMessage(const std::vector<uint8_t>& payload);
        /**
         * @brief Get current rsync handle in the instance.
         *
         * @return RSYNC_HANDLE to be used in all internal calls.
         */
        RSYNC_HANDLE handle()
        {
            return m_handle;
        }

    private:
        RSYNC_HANDLE m_handle;
        bool m_shouldBeRemoved;

};

template <typename T>
class EXPORTED Configuration : public Utils::Builder<T>
{
    protected:
        nlohmann::json m_jsConfiguration;
    public:
        Configuration() = default;
        // LCOV_EXCL_START
        virtual ~Configuration() = default;
        // LCOV_EXCL_STOP
        nlohmann::json& config()
        {
            return m_jsConfiguration;
        }

        /**
         * @brief Set table name.
         *
         * @param table Table name to be queried.
         *
         */
        T& table(const std::string& table)
        {
            m_jsConfiguration["table"] = table;
            return static_cast<T&>(*this); // Return reference to self
        }

        /**
         * @brief Set component name.
         *
         * @param component Component name to be established.
         *
         */
        T& component(const std::string& component)
        {
            m_jsConfiguration["component"] = component;
            return static_cast<T&>(*this); // Return reference to self
        }

        /**
         * @brief Set index.
         *
         * @param index Index to be established.
         *
         */
        T& index(const std::string& index)
        {
            m_jsConfiguration["index"] = index;
            return static_cast<T&>(*this); // Return reference to self
        }

        /**
         * @brief Set last event field.
         *
         * @param lastEvent last event field name to be established.
         *
         */
        T& lastEvent(const std::string& lastEvent)
        {
            m_jsConfiguration["last_event"] = lastEvent;
            return static_cast<T&>(*this); // Return reference to self
        }

        /**
         * @brief Set checksumField name.
         *
         * @param checksumField Component name to be established.
         *
         */
        T& checksumField(const std::string& checksumField)
        {
            m_jsConfiguration["checksum_field"] = checksumField;
            return static_cast<T&>(*this); // Return reference to self
        }
};

class EXPORTED QueryParameter final : public Utils::Builder<QueryParameter>
{
    protected:
        nlohmann::json m_jsQueryParameter;
    public:
        QueryParameter() = default;
        // LCOV_EXCL_START
        virtual ~QueryParameter() = default;
        // LCOV_EXCL_STOP

        /**
         * @brief Get query parameter json.
         *
         * @return Query parameter json.
         */
        const nlohmann::json& queryParameter()
        {
            return m_jsQueryParameter;
        }

        /**
         * @brief Set row filter field.
         *
         * @param rowFilter Field name to be used as a row filter.
         */
        QueryParameter& rowFilter(const std::string& filter);

        /**
         * @brief Set column list to be queried.
         *
         * @param columns Column list to be queried.
         */
        QueryParameter& columnList(const std::vector<std::string>& fields);

        /**
         * @brief Set distinct flag.
         *
         * @param distinct Distinct flag to be set.
         */
        QueryParameter& distinctOpt(const bool distinct);

        /**
         * @brief Set order by field.
         *
         * @param orderBy Field name to be used as order by.
         */
        QueryParameter& orderByOpt(const std::string& orderBy);

        /**
         * @brief Set count field name.
         *
         * @param countFieldName Field name to be used as count.
         */
        QueryParameter& countFieldName(const std::string& countFieldName);

        /**
         * @brief Set count limit value.
         *
         * @param count Count limit to be set.
         */
        QueryParameter& countOpt(const uint32_t count);
};

class EXPORTED RegisterConfiguration final : public Configuration<RegisterConfiguration>
{
    public:
        RegisterConfiguration() = default;
        // LCOV_EXCL_START
        virtual ~RegisterConfiguration() = default;
        // LCOV_EXCL_STOP

        /**
        * @brief Set the decoder type to be applied in the received message.
        *
        * @param decoderType Decoder type to be applied in the received message.
        *
        */
        RegisterConfiguration& decoderType(const std::string& decoderType);

        /**
         * @brief Set the nodata object to be used during the selection of data when all data are requested.
        *
        * @param parameter Nodata object to be used during the selection of data when all data are requested.
        *
        */
        RegisterConfiguration& noData(QueryParameter& parameter);

        /**
         * @brief Set the query parameter to be used during the binary search to get the number of rows.
         *
         * @param parameter Query parameter to be used during the binary search to get the number of rows.
         *
         */
        RegisterConfiguration& countRange(QueryParameter& parameter);

        /**
        * @brief Set the query parameter to be used during the single row search.
        *
        * @param parameter Query parameter to be used during the single row search.
        *
        */
        RegisterConfiguration& rowData(QueryParameter& parameter);

        /**
         * @brief Set the query parameter to be used during the selection of data for the binary search.
         *
         * @param parameter Query parameter to be used during the selection of data for the binary search.
         *
         */
        RegisterConfiguration& rangeChecksum(QueryParameter& parameter);
};

class EXPORTED StartSyncConfiguration final : public Configuration<StartSyncConfiguration>
{
    public:
        StartSyncConfiguration() = default;
        // LCOV_EXCL_START
        virtual ~StartSyncConfiguration() = default;
        // LCOV_EXCL_STOP

        /**
         * @brief Set the query parameter to be used during the selection of data for the binary search on the left side.
         *
         * @param parameter Query parameter to be used during the selection of data for the binary search on the left side.
         *
         */
        StartSyncConfiguration& first(QueryParameter& parameter);

        /**
         * @brief Set the query parameter to be used during the selection of data for the binary search on the right side.
         *
         * @param parameter Query parameter to be used during the selection of data for the binary search on the right side.
         *
         */
        StartSyncConfiguration& last(QueryParameter& parameter);

        /**
         * @brief Set the query parameter to be used during the selection of data used to get the global checksum value.
         *
         * @param parameter Query parameter to be used during the selection of data for to get the global checksum value.
         *
         */
        StartSyncConfiguration& rangeChecksum(QueryParameter& parameter);
};


#endif // _RSYNC_HPP_
