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
#include <vector>
#include "typedef.h"

namespace RSync
{
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
        void push(const RSYNC_HANDLE handle, const std::vector<unsigned char>& data);
    private:

        class RSyncContext final
        {
            public:
                RSyncContext() = default;
                
        };

        std::shared_ptr<RSyncContext> remoteSyncContext(const RSYNC_HANDLE handle);
        
        RSyncImplementation() = default;
        ~RSyncImplementation() = default;
        RSyncImplementation(const RSyncImplementation&) = delete;
        RSyncImplementation& operator=(const RSyncImplementation&) = delete;
        std::map<RSYNC_HANDLE, std::shared_ptr<RSyncContext>> m_remoteSyncContexts;
        std::mutex m_mutex;
    };
}

#endif // _RSYNC_IMPLEMENTATION_H