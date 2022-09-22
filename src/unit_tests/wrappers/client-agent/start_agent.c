/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

int wrap_closesocket(int fd) {
    check_expected(fd);
    return 0;
}

ssize_t wrap_recv(int __fd, void *__buf, size_t __n, int __flags) {
    char* rcv = (char*) mock_ptr_type(char*);
    int len = strlen(rcv);
    snprintf(__buf, len+1, "%s", rcv);
    return len;
}
