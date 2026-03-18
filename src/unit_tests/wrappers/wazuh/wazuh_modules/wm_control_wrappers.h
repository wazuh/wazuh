/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WM_CONTROL_WRAPPERS_H
#define WM_CONTROL_WRAPPERS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

size_t __wrap_wm_control_execute_action(const char *action, const char *service, char **output);
bool __wrap_wm_control_check_systemd(void);
pid_t __wrap_fork(void);

/* Linker-provided real symbol when --wrap,wm_control_check_systemd is enabled. */
extern bool __real_wm_control_check_systemd(void);

#endif
