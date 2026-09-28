/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_HELPER_MAC_H
#define _PROCESS_HELPER_MAC_H

#include <cstdint>
#include <string>
#include <mach/thread_info.h>
#include <sys/proc.h>
#include "sharedDefs.h"

namespace ProcessHelperMac
{
    /**
     * @brief Converts Mach absolute time ticks to POSIX clock ticks.
     *
     * @param machTicks Cumulative Mach time ticks (e.g., from pti_total_user/pti_total_system).
     * @param numer Timebase numerator from mach_timebase_info.
     * @param denom Timebase denominator from mach_timebase_info.
     * @param clkTck Clock ticks per second (from sysconf(_SC_CLK_TCK), typically 100).
     * @return Clock ticks elapsed.
     */
    static inline uint64_t clockTicksFromMachTime(const uint64_t machTicks,
                                                  const uint32_t numer,
                                                  const uint32_t denom,
                                                  const int64_t clkTck)
    {
        if (machTicks == 0 || denom == 0)
        {
            return 0;
        }

        const int64_t effectiveClkTck { clkTck > 0 ? clkTck : 100 };
        const __uint128_t ns { (static_cast<__uint128_t>(machTicks) * numer) / denom };
        return static_cast<uint64_t>((ns * effectiveClkTck) / 1000000000ULL);
    }

    /**
     * @brief Builds the single-character process state. The BSD process status stays at SRUN
     * for any live process, since sleep is tracked per thread, so only a stopped status is
     * taken from it. Otherwise the state is the run state of the main thread, which is what
     * Linux reports for a process. Letters follow the Linux convention where one exists.
     *
     * @param status Process status from proc_bsdinfo.pbi_status.
     * @param mainThreadRunState Run state of the main thread from proc_threadinfo.pth_run_state,
     * or 0 when it could not be read.
     * @return Single character string ("R", "D", "S", "T", "H") or UNKNOWN_VALUE.
     */
    static inline std::string getProcessState(const uint32_t status, const int32_t mainThreadRunState)
    {
        if (status == SSTOP)
        {
            return "T";
        }

        switch (mainThreadRunState)
        {
            case TH_STATE_RUNNING:
                return "R";

            case TH_STATE_UNINTERRUPTIBLE:
                return "D";

            case TH_STATE_WAITING:
                return "S";

            case TH_STATE_STOPPED:
                return "T";

            case TH_STATE_HALTED:
                return "H";

            default:
                return UNKNOWN_VALUE;
        }
    }
} // namespace ProcessHelperMac

#endif // _PROCESS_HELPER_MAC_H
