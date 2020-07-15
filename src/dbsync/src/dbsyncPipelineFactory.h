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
#ifndef PIPE_LINE_FACTORY_H
#define PIPE_LINE_FACTORY_H
#include <map>
#include <mutex>
#include <memory>
#include "typedef.h"

namespace DbSync
{
    using TxnContext = void*;
    using PipelineCtxHandle = void*;
    struct IPipeline
    {
        virtual ~IPipeline() = default;
        virtual void syncRow(const char* syncJson) = 0;
        virtual void getDeleted(result_callback_t callback) = 0;
    };

    class PipelineFactory
    {
    public:
        static PipelineFactory& instance();
        void release();
        PipelineCtxHandle create(const DBSYNC_HANDLE handle,
                                 const TxnContext txnContext,
                                 const int threadNumber,
                                 const int maxQueueSize,
                                 result_callback_t callback);
        const std::shared_ptr<IPipeline>& pipeline(const PipelineCtxHandle handle);
        void destroy(const PipelineCtxHandle handle);
    private:
        PipelineFactory(const PipelineFactory&) = delete;
        PipelineFactory& operator=(const PipelineFactory&) = delete;
        PipelineFactory() = default;
        ~PipelineFactory() = default;
        std::map<PipelineCtxHandle, std::shared_ptr<IPipeline>> m_contexts;
        std::mutex m_contextsMutex;
    };
   
}// namespace DbSync

#endif //PIPE_LINE_FACTORY_H