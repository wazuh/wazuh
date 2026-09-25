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
#include "sharedDefs.h"

#ifndef SIDL
#define SIDL 1
#endif
#ifndef SRUN
#define SRUN 2
#endif
#ifndef SSLEEP
#define SSLEEP 3
#endif
#ifndef SSTOP
#define SSTOP 4
#endif
#ifndef SZOMB
#define SZOMB 5
#endif

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
     * @brief Maps BSD process status (pbi_status) to single-character process state string.
     *
     * @param status Process status from proc_bsdinfo.pbi_status.
     * @return Single character string ("I", "R", "S", "T", "Z") or UNKNOWN_VALUE.
     */
    static inline std::string getProcessState(const uint32_t status)
    {
        switch (status)
        {
            case SIDL:
                return "I";
            case SRUN:
                return "R";
            case SSLEEP:
                return "S";
            case SSTOP:
                return "T";
            case SZOMB:
                return "Z";
            default:
                return UNKNOWN_VALUE;
        }
    }
} // namespace ProcessHelperMac

#endif // _PROCESS_HELPER_MAC_H
