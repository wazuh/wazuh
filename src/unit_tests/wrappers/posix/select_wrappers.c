/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#include "select_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_select(__attribute__((unused)) int nfds,
                  __attribute__((unused)) fd_set *restrict readfds,
                  __attribute__((unused)) fd_set *restrict writefds,
                  __attribute__((unused)) fd_set *restrict errorfds,
                  __attribute__((unused)) struct timeval *restrict timeout) {
    return mock();
}

#endif
