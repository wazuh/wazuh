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

#include <fstream>
#include <sstream>
#include <string>

#ifdef __linux__
#include <sched.h>
#elif defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/sysctl.h>
#include <sys/types.h>
#else
#include <thread>
#endif

namespace proc_detail
{
    /**
     * @brief Convert a CFS CPU quota/period pair into a whole number of cores.
     *
     * A fractional quota (e.g. 500m -> quota 50000 / period 100000) is rounded up so it never
     * collapses to zero threads.
     *
     * @param quota CFS quota in microseconds. A value <= 0 means "no limit" (or invalid input).
     * @param period CFS period in microseconds. Must be > 0 to be meaningful.
     * @return unsigned int ceil(quota / period) with a minimum of 1, or 0 when there is no limit.
     */
    inline unsigned int coresFromQuota(long long quota, long long period)
    {
        if (quota <= 0 || period <= 0)
        {
            return 0u;
        }

        const long long cores = (quota + period - 1) / period; // ceil division
        return cores < 1 ? 1u : static_cast<unsigned int>(cores);
    }

    /**
     * @brief Parse the contents of a cgroups v2 "cpu.max" file into a core count.
     *
     * The file holds a single line "<quota> <period>", where <quota> may be the literal "max"
     * to indicate no limit.
     *
     * @param content Raw file contents.
     * @return unsigned int core count derived from the quota, or 0 when there is no limit / on
     * malformed input.
     */
    inline unsigned int parseCpuMaxV2(const std::string& content)
    {
        std::string quotaStr;
        long long period = 0;
        std::istringstream iss(content);

        if (!(iss >> quotaStr >> period))
        {
            return 0u;
        }

        if (quotaStr == "max")
        {
            return 0u;
        }

        try
        {
            return coresFromQuota(std::stoll(quotaStr), period);
        }
        catch (...)
        {
            return 0u;
        }
    }

#ifdef __linux__
    /**
     * @brief Detect the effective CPU limit imposed by cgroups (v2 first, then v1).
     *
     * @return unsigned int number of cores allowed by the CPU quota, or 0 when no limit is set
     * or the cgroup files are unavailable.
     */
    inline unsigned int cgroupCpuLimit()
    {
        // cgroups v2: /sys/fs/cgroup/cpu.max -> "<quota> <period>" or "max <period>"
        {
            std::ifstream cpuMax("/sys/fs/cgroup/cpu.max");
            if (cpuMax)
            {
                std::string line;
                std::getline(cpuMax, line);
                const unsigned int cores = parseCpuMaxV2(line);
                if (cores > 0u)
                {
                    return cores;
                }
                // A well-formed "max ..." means "no limit"; fall through only if the file was
                // missing/unreadable, which is handled by the ifstream check above.
                return 0u;
            }
        }

        // cgroups v1: cpu.cfs_quota_us (-1 = no limit) and cpu.cfs_period_us
        {
            std::ifstream quotaFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us");
            std::ifstream periodFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us");
            long long quota = 0;
            long long period = 0;

            if (quotaFile && periodFile && (quotaFile >> quota) && (periodFile >> period))
            {
                return coresFromQuota(quota, period);
            }
        }

        return 0u;
    }
#endif
} // namespace proc_detail

/**
 * @brief Get the number of processors available to the current process.
 *
 * On Linux the result is the minimum of the CPU affinity mask size and the cgroup CPU quota
 * (when one is set), so it reflects container/pod CPU limits instead of the full node capacity.
 *
 * @return unsigned int number of processors available to the current process,
 * or 1 if the number cannot be determined.
 */
inline unsigned int cpp_get_nproc()
{
#ifdef __linux__
    cpu_set_t set;
    CPU_ZERO(&set);
    unsigned int affinity = 1u;
    if (sched_getaffinity(0, sizeof(set), &set) == 0)
    {
        const int count = CPU_COUNT(&set);
        affinity = count > 0 ? static_cast<unsigned int>(count) : 1u;
    }

    const unsigned int limit = proc_detail::cgroupCpuLimit();
    return (limit > 0u && limit < affinity) ? limit : affinity;
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
