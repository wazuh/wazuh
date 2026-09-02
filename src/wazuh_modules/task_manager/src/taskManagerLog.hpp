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

#ifndef _TASK_MANAGER_LOG_HPP
#define _TASK_MANAGER_LOG_HPP

#include <loggerHelper.h>

namespace task_manager
{
    /// Tag for this module's log lines. A literal rather than modulesd's ARGV0, matching the other
    /// C++ modules, so an operator can tell the task manager's output apart in wazuh-manager.log.
    constexpr auto TASK_MANAGER_LOGTAG {"wazuh-manager-modulesd:task-manager"};

    /*
     * Sub-tags for the three subsystems whose lines an operator most often needs to separate.
     *
     * The `:suffix` form is load-bearing: LogFn::compose() truncates from the first '(', so a
     * parenthesised suffix would be discarded while a colon survives.
     */
    constexpr auto TASK_MANAGER_EXECUTOR_LOGTAG {"wazuh-manager-modulesd:task-manager:executor"};
    constexpr auto TASK_MANAGER_SCHEDULER_LOGTAG {"wazuh-manager-modulesd:task-manager:scheduler"};
    constexpr auto TASK_MANAGER_HTTP_LOGTAG {"wazuh-manager-modulesd:task-manager:http"};

    /// Not a member of anything: LogFn has hidden ELF visibility, so holding one as a field of a
    /// default-visibility class trips -Wattributes. A function-local static also costs one
    /// construction ever rather than one per log call.
    inline const LogFn& moduleLogFn()
    {
        static const LogFn instance {TASK_MANAGER_LOGTAG};
        return instance;
    }

    inline const LogFn& executorLogFn()
    {
        static const LogFn instance {TASK_MANAGER_EXECUTOR_LOGTAG};
        return instance;
    }

    inline const LogFn& schedulerLogFn()
    {
        static const LogFn instance {TASK_MANAGER_SCHEDULER_LOGTAG};
        return instance;
    }

    inline const LogFn& httpLogFn()
    {
        static const LogFn instance {TASK_MANAGER_HTTP_LOGTAG};
        return instance;
    }
} // namespace task_manager

#endif // _TASK_MANAGER_LOG_HPP
