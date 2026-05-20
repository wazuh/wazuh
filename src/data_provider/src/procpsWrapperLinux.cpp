/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "procpsWrapperLinux.hpp"

#include <memory>
#include <mutex>

namespace
{
    std::mutex g_procpsMutex;

    struct ProcTabDeleter
    {
        void operator()(PROCTAB* pt) const
        {
            if (pt)
            {
                closeproc(pt);
            }
        }
    };

    struct ProcDeleter
    {
        void operator()(proc_t* p) const
        {
            if (p)
            {
                freeproc(p);
            }
        }
    };
}

void ProcpsWrapper::scanProcesses(int flags, const ProcCallback& callback)
{
    std::lock_guard<std::mutex> lock(g_procpsMutex);

    std::unique_ptr<PROCTAB, ProcTabDeleter> proctab{openproc(flags)};

    if (!proctab)
    {
        return;
    }

    while (auto* raw = readproc(proctab.get(), nullptr))
    {
        std::unique_ptr<proc_t, ProcDeleter> process{raw};
        callback(process.get());
    }
}
