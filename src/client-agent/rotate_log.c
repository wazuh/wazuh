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

// Thread to rotate internal log
void * w_rotate_log_thread(__attribute__((unused)) void * arg) {
    time_t tm = time(NULL);
    struct tm *p = localtime(&tm);
    int today = p->tm_mday;
    int compress = getDefine_Int("monitord", "compress", 0, 1);
    int keep_log_days = getDefine_Int("monitord", "keep_log_days", 0, 500);

    debug1("%s: Log rotating thread started.", __local_name);

    while (1) {
        tm = time(NULL);
        p = localtime(&tm);

        if (today != p->tm_mday) {
            /* Rotate and compress ossec.log */
            w_rotate_log(p, compress, keep_log_days);
            today = p->tm_mday;
        }

        sleep(1);
    }
}
