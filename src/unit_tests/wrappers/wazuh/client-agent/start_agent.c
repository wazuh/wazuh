/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "shared.h"
#include "start_agent.h"

#include <stdio.h> 
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

ssize_t wrap_recv(__attribute__((unused)) int __fd, __attribute__((unused)) void *__buf,
                  __attribute__((unused)) size_t __n, __attribute__((unused)) int __flags) {
    char* rcv = (char*) mock_ptr_type(char*);
    int len = strlen(rcv);
    snprintf(__buf, len+1, "%s", rcv);
    return len;
}
