/**
 * @file rotate_log.cpp
 * @brief C++17 implementation of internal log rotation.
 *
 * Replaces rotate_log.c.  The LogRotator class reads monitord
 * config values and runs a loop that checks daily and size-based
 * rotation triggers for ossec.log / ossec.json.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "log_rotator.hpp"

#include <ctime>
#include <sys/stat.h>

extern "C"
{
#include "log_rotate.h"
}

#ifdef WIN32
#define localtime_r(x, y) localtime_s(y, x)
#endif

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────────

    LogRotator& LogRotator::instance()
    {
        static LogRotator inst;
        return inst;
    }

    // ── Configuration ────────────────────────────────────────────────────

    void LogRotator::loadConfig()
    {
        log_compress_ = getDefine_Int("monitord", "compress", 0, 1);
        keep_log_days_ = getDefine_Int("monitord", "keep_log_days", 0, 500);
        day_wait_ = getDefine_Int("monitord", "day_wait", 0, 600);
        size_rotate_read_ = getDefine_Int("monitord", "size_rotate", 0, 4096);
        daily_rotations_ = getDefine_Int("monitord", "daily_rotations", 1, 256);
    }

    // ── Main loop ────────────────────────────────────────────────────────

    void LogRotator::run()
    {
        const unsigned long size_rotate = static_cast<unsigned long>(size_rotate_read_) * 1024UL * 1024UL;

        mdebug1("Log rotating thread started.");

        char path[PATH_MAX];
        char path_json[PATH_MAX];
        snprintf(path, PATH_MAX, "%s", LOGFILE);
        snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);

        std::time_t now = std::time(nullptr);
        struct tm tm {};
        localtime_r(&now, &tm);
        int today = tm.tm_mday;

        while (true)
        {
            now = std::time(nullptr);
            localtime_r(&now, &tm);

            // Daily rotation
            if (today != tm.tm_mday)
            {
                std::this_thread::sleep_for(std::chrono::seconds(day_wait_));
                w_rotate_log(log_compress_, keep_log_days_, 1, 0, daily_rotations_);
                today = tm.tm_mday;
            }

            // Size-based rotation
            if (size_rotate > 0)
            {
                struct stat buf {};

                if (w_stat(path, &buf) == 0)
                {
                    if (static_cast<unsigned long>(buf.st_size) >= size_rotate)
                    {
                        w_rotate_log(log_compress_, keep_log_days_, 0, 0, daily_rotations_);
                    }
                }

                if (w_stat(path_json, &buf) == 0)
                {
                    if (static_cast<unsigned long>(buf.st_size) >= size_rotate)
                    {
                        w_rotate_log(log_compress_, keep_log_days_, 0, 1, daily_rotations_);
                    }
                }
            }
            else
            {
                mdebug1("Disabled rotation of internal logs by size.");
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines + globals
// =====================================================================

extern "C"
{

    // Globals declared "extern" in agentd.h, read by config.c
    int log_compress;
    int keep_log_days;
    int day_wait;
    int daily_rotations;
    int size_rotate_read;

#ifdef WIN32
    DWORD WINAPI w_rotate_log_thread(__attribute__((unused)) LPVOID arg)
#else
    void* w_rotate_log_thread(__attribute__((unused)) void* arg)
#endif
    {
        auto& rotator = agentd::LogRotator::instance();
        rotator.loadConfig();

        // Sync extern globals so other C code can read them
        log_compress = rotator.logCompress();
        keep_log_days = rotator.keepLogDays();
        day_wait = rotator.dayWait();
        size_rotate_read = rotator.sizeRotateRead();
        daily_rotations = rotator.dailyRotations();

        rotator.run(); // never returns

#ifdef WIN32
        return 0;
#else
        return nullptr;
#endif
    }

} // extern "C"
