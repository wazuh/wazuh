/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "task_manager.h"

#include "taskManagerFacade.hpp"
#include "taskManagerLog.hpp"

#include <exception>
#include <memory>
#include <mutex>

namespace Log
{
    // Storage for the `extern` declared in loggerHelper.h. Each binary or DSO that pulls in that
    // header needs its own definition -- it is deliberately not `inline` there, so
    // GLOBAL_LOG_FUNCTION stays private per-DSO instead of being merged across them.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

namespace
{
    std::mutex gLifecycleMutex;
    std::unique_ptr<task_manager::TaskManagerFacade> gFacade;
} // namespace

extern "C"
{
    int task_manager_start(full_log_fnc_t callbackLog,
                           const task_manager_config_t* config,
                           const task_manager_host_ops_t* hostOps)
    {
        // NOTHING may cross back into C as an exception. modulesd calls this from a plain C
        // routine, and unwinding through it is undefined.
        try
        {
            if (config == nullptr || hostOps == nullptr)
            {
                return -1;
            }

            std::lock_guard lock {gLifecycleMutex};

            if (callbackLog != nullptr)
            {
                Log::assignLogFunction(callbackLog);
            }

            if (!gFacade)
            {
                gFacade = std::make_unique<task_manager::TaskManagerFacade>();
            }

            gFacade->start(*config, *hostOps);
            return 0;
        }
        catch (const std::exception& exception)
        {
            if (Log::GLOBAL_LOG_FUNCTION)
            {
                LOGFN_ERROR(task_manager::moduleLogFn(), "Task manager failed to start: %s", exception.what());
            }
            return -1;
        }
        catch (...)
        {
            return -1;
        }
    }

    void task_manager_stop(void)
    {
        try
        {
            std::lock_guard lock {gLifecycleMutex};

            if (gFacade)
            {
                gFacade->stop();
                gFacade.reset();
            }
        }
        catch (...) // NOLINT(bugprone-empty-catch)
        {
            // Stopping is best-effort by definition, and this is called from modulesd's shutdown
            // path where there is nothing useful left to do about a failure.
        }
    }
}
