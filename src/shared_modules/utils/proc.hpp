/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * June 29, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef PROC_HPP
#define PROC_HPP

#ifdef __linux__
#include <sched.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/types.h>
#else
#include <thread>
#endif

/**
 * @brief Get the number of processors available to the current process.
 *
 * @return unsigned int number of processors available to the current process,
 * or 1 if the number cannot be determined.
 */
inline unsigned int cpp_get_nproc()
{
#ifdef __linux__
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(0, sizeof(set), &set) < 0)
    {
        return 1u;
    }
    return static_cast<unsigned int>(CPU_COUNT(&set));
#elif defined(__APPLE__) || defined(__FreeBSD__)
    int count = 1;
    size_t len = sizeof(count);
    sysctlbyname("hw.logicalcpu", &count, &len, nullptr, 0);
    return static_cast<unsigned int>(count > 0 ? count : 1);
#else
    const auto count = std::thread::hardware_concurrency();
    return count > 0u ? count : 1u;
#endif
}

#endif // PROC_HPP
