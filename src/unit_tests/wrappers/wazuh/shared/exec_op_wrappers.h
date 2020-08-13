/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef EXEC_OP_WRAPPERS_H
#define EXEC_OP_WRAPPERS_H

#ifdef WIN32
#include <processthreadsapi.h>
#endif
#include <stdio.h>
#include <sys/types.h>
#include "../headers/exec_op.h"

int __wrap_wpclose();

wfd_t *__wrap_wpopenl();

wfd_t *__wrap_wpopenv();

#endif
