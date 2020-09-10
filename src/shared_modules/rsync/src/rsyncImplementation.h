/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * August 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSYNC_IMPLEMENTATION_H
#define _RSYNC_IMPLEMENTATION_H
#include <map>
#include <memory>
#include <mutex>
#include <functional>
#include "typedef.h"
#include "json.hpp"
#include "msgDispatcher.h"
#include "syncDecoder.h"
#include "dbsync.h"

struct CJsonDeleter
{
    void operator()(char* json)
    {
        cJSON_free(json);
    }
    void operator()(cJSON* json)
    {
        cJSON_Delete(json);
    }
};

namespace RSync
{
    
    static std::map<std::string, SyncMsgBodyType> SyncMsgBodyTypeMap
    {
        { "JSON_RANGE", SYNC_RANGE_JSON }
    };

    using ResultCallback = std::function<void(const std::string&)>;
    using MsgDispatcher = Utils::MsgDispatcher<std::string, SyncInputData, std::vector<unsigned char>, SyncDecoder>;

    class RSyncImplementation final
    {
    public:
        static RSyncImplementation& instance()
        {
            static RSyncImplementation s_instance;
            return s_instance;
        }

        void release();

        bool releaseContext(const RSYNC_HANDLE handle);

        RSYNC_HANDLE create();

        void registerSyncId(const RSYNC_HANDLE handle, 
                            const std::string& message_header_id, 
                            const DBSYNC_HANDLE dbsync_handle, 
                            const char* sync_configuration, 
                            const ResultCallback callbackWrapper);

        
    private:

        class RSyncContext final
        {
            public:
                RSyncContext() = default;
                MsgDispatcher m_msgDispatcher;
        };

        std::shared_ptr<RSyncContext> remoteSyncContext(const RSYNC_HANDLE handle);

        static size_t getRangeCount(const DBSYNC_HANDLE dbsync_handle, 
                             const nlohmann::json& rangeCountQuery, 
                             const SyncInputData& syncData);

        static std::string getChecksum(const DBSYNC_HANDLE dbsync_handle, 
                                 const nlohmann::json& rangeQuery,
                                 const std::string& begin,
                                 const std::string& end);

        static nlohmann::json getRowData(const DBSYNC_HANDLE dbsync_handle, 
                                         const nlohmann::json& rowQuery,
                                         const std::string& index);

        static void sendAllData(const DBSYNC_HANDLE dbsync_handle, 
                                const nlohmann::json& noDataQuery,
                                const ResultCallback callbackWrapper);
        
        RSyncImplementation() = default;
        ~RSyncImplementation() = default;
        RSyncImplementation(const RSyncImplementation&) = delete;
        RSyncImplementation& operator=(const RSyncImplementation&) = delete;
        std::map<RSYNC_HANDLE, std::shared_ptr<RSyncContext>> m_remoteSyncContexts;
        std::mutex m_mutex;
    };
}

#endif // _RSYNC_IMPLEMENTATION_H