/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
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
#include <functional>
#include "dbengine.h"
#include "commonDefs.h"

namespace DbSync
{
    using TxnContext = void*;
    using PipelineCtxHandle = void*;
    struct IPipeline
    {
        // LCOV_EXCL_START
        virtual ~IPipeline() = default;
        // LCOV_EXCL_STOP
        virtual void syncRow(const nlohmann::json& syncJson) = 0;
        virtual void getDeleted(const ResultCallback callback) = 0;
    };

    class PipelineFactory final
    {
        public:
            static PipelineFactory& instance() noexcept;
            void release() noexcept;
            PipelineCtxHandle create(const DBSYNC_HANDLE    handle,
                                     const nlohmann::json&  tables,
                                     const unsigned int     threadNumber,
                                     const unsigned int     maxQueueSize,
                                     const ResultCallback   callback);
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
