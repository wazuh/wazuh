/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include <time.h>                 /* struct timespec */

#include "batch_queue_op_wrappers.h"

/* ----------------------------- enqueue ---------------------------- */

int __wrap_batch_queue_enqueue_ex(w_rr_queue_t *sched, const char *agent_key, void *data) {
    check_expected(sched);
    check_expected(agent_key);
    check_expected(data);

    return mock_type(int);
}
