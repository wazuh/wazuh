/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SIGNAL_WRAPPERS_H
#define SIGNAL_WRAPPERS_H

#include <signal.h>
#include <sys/types.h>

int __wrap_kill(pid_t pid, int sig);

pid_t __wrap_waitpid(pid_t pid, int * wstatus, int options);

#endif // SIGNAL_WRAPPERS_H
