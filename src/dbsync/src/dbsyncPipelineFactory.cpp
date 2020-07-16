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

#include <tuple>
#include "db_exception.h"
#include "dbsyncPipelineFactory.h"
#include "pipelineNodesImp.h"

namespace DbSync
{

    struct CJsonDeleter
    {
        void operator()(cJSON* json)
        {
            cJSON_Delete(json);
        }
    };

    class Pipeline : public IPipeline
    {
    public:

        Pipeline(const DBSYNC_HANDLE handle,
                 const TxnContext txnContext,
                 const unsigned int threadNumber,
                 const unsigned int maxQueueSize,
                 ResultCallback callback)
        : m_spDispatchNode{ maxQueueSize ? getDispatchNode(threadNumber) : nullptr }
        , m_spSyncNode{ maxQueueSize ? getSyncNode(threadNumber) : nullptr}
        , m_handle{ handle }
        , m_txnContext{ txnContext }
        , m_maxQueueSize{ maxQueueSize }
        , m_callback{ callback }
        {
            if (!m_callback || !m_handle || !m_txnContext)
            {
                throw dbsync_error
                {
                    3, "PipelineFactory, Invalid parameters."
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
                }
                catch(...)
                {}
            }
        }
        void syncRow(const char* value) override
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
        void getDeleted(ResultCallback /*callback*/) override
        {
            if (m_spSyncNode)
            {
                m_spSyncNode->rundown();
            }
            // DBSyncImplementation::instance().getDeleted(m_handle, m_txnContext, calback);
        }
    private:
        using SyncResult = std::tuple<ReturnTypeCallback, std::string>;
        using DispatchCallbackNode = Utils::ReadNode<SyncResult>;
        using SyncRowNode = Utils::ReadWriteNode<const char*, SyncResult, DispatchCallbackNode>;

        std::shared_ptr<DispatchCallbackNode> getDispatchNode(const int threadNumber)
        {
            return std::make_shared<DispatchCallbackNode>
            (
                std::bind(&Pipeline::dispatchResult, this, std::placeholders::_1),
                threadNumber
            );
        }
        std::shared_ptr<SyncRowNode> getSyncNode(const int threadNumber)
        {
            return std::make_shared<SyncRowNode>
            (
                std::bind(&Pipeline::processSyncRow, this, std::placeholders::_1),
                threadNumber
            );
        }

        SyncResult processSyncRow(const char* value)
        {
            ReturnTypeCallback type{ MODIFIED };
            std::string result{value};
            // DBSyncImplementation::instance().syncTxRow(m_handle, m_txnContext, value, type, result);
            return std::make_tuple<ReturnTypeCallback, std::string>(std::move(type), std::move(result));
        }
        void dispatchResult(const SyncResult& result)
        {
            const auto value{ std::get<1>(result) };
            if (!value.empty())
            {
                const std::unique_ptr<cJSON, CJsonDeleter> spJsonBytes{cJSON_Parse(value.c_str())};
                m_callback(std::get<0>(result), spJsonBytes.get());
            }
        }
        const std::shared_ptr<DispatchCallbackNode> m_spDispatchNode;
        const std::shared_ptr<SyncRowNode> m_spSyncNode;
        const DBSYNC_HANDLE m_handle;
        const TxnContext m_txnContext;
        const unsigned int m_maxQueueSize;
        const ResultCallback m_callback;
    };
//----------------------------------------------------------------------------------------
    PipelineFactory& PipelineFactory::instance()
    {
        static PipelineFactory s_instance;
        return s_instance;
    }
    void PipelineFactory::release()
    {
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        m_contexts.clear();
    }
    PipelineCtxHandle PipelineFactory::create(const DBSYNC_HANDLE handle,
                                              const TxnContext txnContext,
                                              const unsigned int threadNumber,
                                              const unsigned int maxQueueSize,
                                              ResultCallback callback)
    {
        std::shared_ptr<IPipeline> spContext
        {
            new Pipeline
            {
                handle, txnContext, threadNumber, maxQueueSize, callback
            }
        };
        const auto ret { spContext.get() };
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        m_contexts.emplace(ret, spContext);
        return ret;
    }
    const std::shared_ptr<IPipeline>& PipelineFactory::pipeline(const PipelineCtxHandle handle)
    {
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        const auto it
        {
            m_contexts.find(handle)
        };
        if (it == m_contexts.end())
        {
            throw dbsync_error
            {
                2, "PipelineFactory, Invalid handle value."
            };
        }
        return it->second;
    }
    void PipelineFactory::destroy(const PipelineCtxHandle handle)
    {
        std::lock_guard<std::mutex> lock{ m_contextsMutex };
        const auto it
        {
            m_contexts.find(handle)
        };
        if (it == m_contexts.end())
        {
            throw dbsync_error
            {
                2, "PipelineFactory, Invalid handle value."
            };
        }
        m_contexts.erase(it);   
    }
}// namespace DbSync
