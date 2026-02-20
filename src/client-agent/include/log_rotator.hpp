/**
 * @file log_rotator.hpp
 * @brief C++17 replacement for rotate_log.c
 *
 * Encapsulates the internal-log rotation thread that monitors
 * ossec.log / ossec.json for size and daily rotation.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_LOG_ROTATOR_HPP
#define AGENTD_LOG_ROTATOR_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Manages periodic rotation of internal log files.
     *
     * Reads configuration once on init, then runs an infinite loop
     * checking daily and size-based rotation triggers.
     */
    class LogRotator
    {
    public:
        LogRotator() = default;
        ~LogRotator() = default;

        LogRotator(const LogRotator&) = delete;
        LogRotator& operator=(const LogRotator&) = delete;

        /**
         * Load configuration from internal_options.conf.
         * Must be called before run().
         */
        void loadConfig();

        /**
         * Main loop: monitors log files and rotates as needed.
         * Designed to run in its own thread (never returns).
         * Requires loadConfig() to have been called first.
         */
        void run();

        /** Access the singleton. */
        static LogRotator& instance();

        // ── Accessors for the config values (used by config.c via extern globals) ──
        int logCompress() const noexcept
        {
            return log_compress_;
        }
        int keepLogDays() const noexcept
        {
            return keep_log_days_;
        }
        int dayWait() const noexcept
        {
            return day_wait_;
        }
        int dailyRotations() const noexcept
        {
            return daily_rotations_;
        }
        int sizeRotateRead() const noexcept
        {
            return size_rotate_read_;
        }

    private:
        int log_compress_ {0};
        int keep_log_days_ {0};
        int day_wait_ {0};
        int daily_rotations_ {0};
        int size_rotate_read_ {0};
    };

} // namespace agentd

#endif // AGENTD_LOG_ROTATOR_HPP
