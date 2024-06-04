/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
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
#include <shared_mutex>
#include <memory>
#include "commonDefs.h"
#include "json.hpp"
#include "registrationController.hpp"
#include "msgDispatcher.h"
#include "syncDecoder.h"
#include "dbsyncWrapper.h"
#include "cjsonSmartDeleter.hpp"
#include "synchronizationController.hpp"

namespace RSync
{
    enum IntegrityMsgType
    {
        INTEGRITY_CHECK_LEFT,       ///< Splitted chunk: left part.
        INTEGRITY_CHECK_RIGHT,      ///< Splitted chunk: right part.
        INTEGRITY_CHECK_GLOBAL,     ///< Global chunk (all files).
        INTEGRITY_CLEAR             ///< Clear data (no files at all).
    };

    static std::map<IntegrityMsgType, std::string> IntegrityCommands
    {
        { INTEGRITY_CHECK_LEFT, "integrity_check_left" },
        { INTEGRITY_CHECK_RIGHT, "integrity_check_right" },
        { INTEGRITY_CHECK_GLOBAL, "integrity_check_global" },
        { INTEGRITY_CLEAR, "integrity_clear" }
    };

    struct SplitContext
    {
        std::string checksum;
        std::string tail;
        std::string begin;
        std::string end;
        int32_t id;
        IntegrityMsgType type;
    };

    enum CalcChecksumType
    {
        CHECKSUM_COMPLETE,
        CHECKSUM_SPLIT
    };

    struct ChecksumContext
    {
        SplitContext leftCtx;
        SplitContext rightCtx;
        CalcChecksumType type;
        size_t size;
    };

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

            void releaseContext(const RSYNC_HANDLE handle);

            RSYNC_HANDLE create(const unsigned int threadPoolSize = std::thread::hardware_concurrency(),
                                const size_t maxQueueSize = UNLIMITED_QUEUE_SIZE);

            void startRSync(const RSYNC_HANDLE handle,
                            const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                            const nlohmann::json& startConfiguration,
                            const ResultCallback callbackWrapper);

            void registerSyncId(const RSYNC_HANDLE handle,
                                const std::string& messageHeaderId,
                                const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                const nlohmann::json& syncConfiguration,
                                const ResultCallback callbackWrapper);

            void push(const RSYNC_HANDLE handle,
                      const std::vector<unsigned char>& data);

            bool isComponentRegistered(const std::string& component);


        private:

            class RSyncContext final
            {
                public:
                    RSyncContext(const unsigned int threadPoolSize, const size_t maxQueueSize)
                        : m_msgDispatcher { std::make_shared<MsgDispatcher>(threadPoolSize, maxQueueSize) }
                    { }
                    std::shared_ptr<MsgDispatcher> m_msgDispatcher;
            };

            std::shared_ptr<RSyncContext> remoteSyncContext(const RSYNC_HANDLE handle);

            static size_t getRangeCount(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                        const nlohmann::json& jsonSyncConfiguration,
                                        const SyncInputData& syncData);

            static void fillChecksum(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                     const nlohmann::json& jsonConfiguration,
                                     const std::string& begin,
                                     const std::string& end,
                                     ChecksumContext& ctx);

            static nlohmann::json getRowData(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                             const nlohmann::json& jsonSyncConfiguration,
                                             const std::string& index = "");

            static nlohmann::json executeSelectQuery(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                                     const std::string& table,
                                                     const nlohmann::json& jsFirstQuery,
                                                     const nlohmann::json& jsLastQuery);

            static void sendAllData(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                    const nlohmann::json& jsonSyncConfiguration,
                                    const ResultCallback callbackWrapper,
                                    const SyncInputData& ctx);

            static void sendChecksumFail(const std::shared_ptr<DBSyncWrapper>& spDBSyncWrapper,
                                         const nlohmann::json& jsonSyncConfiguration,
                                         const ResultCallback callbackWrapper,
                                         const SyncInputData syncData);

            RSyncImplementation() = default;
            ~RSyncImplementation() = default;
            RSyncImplementation(const RSyncImplementation&) = delete;
            RSyncImplementation& operator=(const RSyncImplementation&) = delete;
            std::map<RSYNC_HANDLE, std::shared_ptr<RSyncContext>> m_remoteSyncContexts;
            std::mutex m_mutex;
            RegistrationController m_registrationController;
            static SynchronizationController m_synchronizationController;
    };
}// namespace RSync

#endif // _RSYNC_IMPLEMENTATION_H
