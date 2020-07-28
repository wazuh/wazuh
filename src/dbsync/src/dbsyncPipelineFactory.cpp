/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <utility>
#include "db_exception.h"
#include "dbsyncPipelineFactory.h"
#include "dbsync_implementation.h"
#include "pipelineNodesImp.h"

namespace DbSync
{
    class Pipeline final : public IPipeline
    {
    public:

        Pipeline(const DBSYNC_HANDLE handle,
                 const char* tables,
                 const unsigned int threadNumber,
                 const unsigned int maxQueueSize,
                 const ResultCallback callback)
        : m_spDispatchNode{ maxQueueSize ? getDispatchNode(threadNumber) : nullptr }
        , m_spSyncNode{ maxQueueSize ? getSyncNode(threadNumber) : nullptr}
        , m_handle{ handle }
        , m_txnContext{ DBSyncImplementation::instance().createTransaction(handle, tables) }
        , m_maxQueueSize{ maxQueueSize }
        , m_callback{ callback }
        {
            if (!m_callback || !m_handle || !m_txnContext)
            {
                throw dbsync_error
                {
                    INVALID_PARAMETERS
                };
            }
            Utils::connect(m_spSyncNode, m_spDispatchNode);
        }
        ~Pipeline()
        {
            if (m_spDispatchNode)
            {
                try
                {
                    m_spDispatchNode->rundown();
                    DBSyncImplementation::instance().closeTransaction(m_handle, m_txnContext);
                }
                catch(...)
                {}
            }
        }
        void syncRow(const nlohmann::json& value) override
        {
            const auto async{ m_spSyncNode && m_spSyncNode->size() < m_maxQueueSize };
            if (async)
            {
                m_spSyncNode->receive(value);
            }
            else
            {
                //sync will be processed in the host thread instead of a worker thread.
                const auto result{ processSyncRow(value) };
                dispatchResult(result);
            }
        }
        void getDeleted(ResultCallback callback) override
        {
            if (m_spSyncNode)
            {
                m_spSyncNode->rundown();
            }
            DBSyncImplementation::instance().getDeleted(m_handle, m_txnContext, callback);
        }
    private:
        using SyncResult = std::pair<ReturnTypeCallback, nlohmann::json>;
        using DispatchCallbackNode = Utils::ReadNode<SyncResult>;
        using SyncRowNode = Utils::ReadWriteNode<nlohmann::json, SyncResult, DispatchCallbackNode>;

        std::shared_ptr<DispatchCallbackNode> getDispatchNode(const int threadNumber)
        {
            return std::make_shared<DispatchCallbackNode>
            (
                std::bind(&Pipeline::dispatchResult, this, std::placeholders::_1),
                threadNumber ? threadNumber : std::thread::hardware_concurrency()
            );
        }
        std::shared_ptr<SyncRowNode> getSyncNode(const int threadNumber)
        {
            return std::make_shared<SyncRowNode>
            (
                std::bind(&Pipeline::processSyncRow, this, std::placeholders::_1),
                threadNumber ? threadNumber : std::thread::hardware_concurrency()
            );
        }

        SyncResult processSyncRow(const nlohmann::json& value)
        {
            SyncResult result{};
            try
            {
                DBSyncImplementation::instance().syncRowData
                (
                    m_handle,
                    m_txnContext,
                    value.dump().c_str(),
                    [&result](ReturnTypeCallback resType, const nlohmann::json& resValue)
                    {
                        result.first = resType;
                        result.second = resValue;
                    }
                );
            }
            catch(const DbSync::max_rows_error&)
            {
                result.first = MAX_ROWS;
                result.second = value;
            }
            catch(...)
            {
                result.first = DB_ERROR;
                result.second = value;
            }
            return result;
        }
        void dispatchResult(const SyncResult& result)
        {
            const auto& value{ result.second };
            if (!value.empty())
            {
                m_callback(result.first, value);
            }
        }
        const std::shared_ptr<DispatchCallbackNode> m_spDispatchNode;
        const std::shared_ptr<SyncRowNode> m_spSyncNode;
        const DBSYNC_HANDLE m_handle;
        const TXN_HANDLE m_txnContext;
        const unsigned int m_maxQueueSize;
        const ResultCallback m_callback;
    };
//----------------------------------------------------------------------------------------
    PipelineFactory& PipelineFactory::instance() noexcept
    {
        static PipelineFactory s_instance;
        return s_instance;
    }
    void PipelineFactory::release() noexcept
    {
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        m_contexts.clear();
    }
    PipelineCtxHandle PipelineFactory::create(const DBSYNC_HANDLE handle,
                                              const char* tables,
                                              const unsigned int threadNumber,
                                              const unsigned int maxQueueSize,
                                              const ResultCallback callback)
    {
        const auto spContext
        {
            std::make_shared<Pipeline>(handle, tables, threadNumber, maxQueueSize, callback)
        };
        const auto ret { spContext.get() };
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        m_contexts.emplace(ret, spContext);
        return ret;
    }
    const std::shared_ptr<IPipeline>& PipelineFactory::pipeline(const PipelineCtxHandle handle)
    {
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        const auto& it
        {
            m_contexts.find(handle)
        };
        if (it == m_contexts.end())
        {
            throw dbsync_error
            {
                INVALID_HANDLE
            };
        }
        return it->second;
    }
    void PipelineFactory::destroy(const PipelineCtxHandle handle)
    {
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        const auto& it
        {
            m_contexts.find(handle)
        };
        if (it == m_contexts.end())
        {
            throw dbsync_error
            {
                INVALID_HANDLE
            };
        }
        m_contexts.erase(it);   
    }
}// namespace DbSync
