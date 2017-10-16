/* Copyright (C) 2017 Wazuh Inc.
 * June 13, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agentd.h"
#include "monitord/monitord.h"

#ifdef WIN32
#define localtime_r(x, y) localtime_s(y, x)
#endif

// Thread to rotate internal log
void * w_rotate_log_thread(__attribute__((unused)) void * arg) {
    time_t now = time(NULL);
    struct tm tm;
    int today;
    int compress = getDefine_Int("monitord", "compress", 0, 1);
    int keep_log_days = getDefine_Int("monitord", "keep_log_days", 0, 500);
    int day_wait = getDefine_Int("monitord", "day_wait", 5, 240);

    mdebug1("Log rotating thread started.");

    localtime_r(&now, &tm);
    today = tm.tm_mday;

    while (1) {
        now = time(NULL);
        localtime_r(&now, &tm);

        if (today != tm.tm_mday) {
            sleep(day_wait);
            /* Rotate and compress ossec.log */
            w_rotate_log(compress, keep_log_days);
            today = tm.tm_mday;
        }

        sleep(1);
    }
}
