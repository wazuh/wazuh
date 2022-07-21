/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WAIT_WRAPPERS_H
#define WAIT_WRAPPERS_H

#include <sys/types.h>
#include <sys/wait.h>

pid_t __wrap_waitpid(pid_t __pid, int * wstatus, int __options);

#endif // WAIT_WRAPPERS_H
