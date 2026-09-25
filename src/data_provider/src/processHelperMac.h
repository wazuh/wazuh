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

#ifndef SSTOP
#define SSTOP 4
#endif
#ifndef SZOMB
#define SZOMB 5
#endif

#ifndef TH_STATE_RUNNING
#define TH_STATE_RUNNING 1
#endif
#ifndef TH_STATE_STOPPED
#define TH_STATE_STOPPED 2
#endif
#ifndef TH_STATE_WAITING
#define TH_STATE_WAITING 3
#endif
#ifndef TH_STATE_UNINTERRUPTIBLE
#define TH_STATE_UNINTERRUPTIBLE 4
#endif
#ifndef TH_STATE_HALTED
#define TH_STATE_HALTED 5
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
     * @brief Rank used when no thread state is available. Lower ranks take precedence.
     */
    constexpr int THREAD_STATE_RANK_UNKNOWN { 7 };

    /**
     * @brief Ranks a thread run state the same way macOS ps does, so the busiest thread
     * of a process determines its state.
     *
     * @param runState Thread run state from proc_threadinfo.pth_run_state.
     * @param sleepTime Seconds the thread has been sleeping, from proc_threadinfo.pth_sleep_time.
     * @return Rank from 1 (running) to 6 (halted), or THREAD_STATE_RANK_UNKNOWN.
     */
    static inline int threadStateRank(const int32_t runState, const int32_t sleepTime)
    {
        switch (runState)
        {
            case TH_STATE_RUNNING:
                return 1;

            case TH_STATE_UNINTERRUPTIBLE:
                return 2;

            case TH_STATE_WAITING:
                return sleepTime > 20 ? 4 : 3;

            case TH_STATE_STOPPED:
                return 5;

            case TH_STATE_HALTED:
                return 6;

            default:
                return THREAD_STATE_RANK_UNKNOWN;
        }
    }

    /**
     * @brief Builds the single-character process state. The BSD process status only tracks
     * stopped and zombie processes reliably; any other process is reported as running, so
     * its state comes from the lowest thread rank.
     *
     * Unlike ps, threads idle for more than 20 seconds are reported as "S" rather than "I".
     * That split depends only on how long a thread has slept, so it would flip between scans
     * for processes that wake up periodically and report a change each time.
     *
     * @param status Process status from proc_bsdinfo.pbi_status.
     * @param threadRank Lowest threadStateRank() among the process threads.
     * @return Single character string ("R", "U", "S", "T", "H", "Z") or UNKNOWN_VALUE.
     */
    static inline std::string getProcessState(const uint32_t status, const int threadRank)
    {
        switch (status)
        {
            case SSTOP:
                return "T";

            case SZOMB:
                return "Z";

            default:
                break;
        }

        constexpr char RANK_STATES[] { "RUSSTH" };

        if (threadRank >= 1 && threadRank < THREAD_STATE_RANK_UNKNOWN)
        {
            return std::string(1, RANK_STATES[threadRank - 1]);
        }

        return UNKNOWN_VALUE;
    }
} // namespace ProcessHelperMac

#endif // _PROCESS_HELPER_MAC_H
