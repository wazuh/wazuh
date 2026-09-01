/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MACOS_LOG_WRAPPERS_H
#define MACOS_LOG_WRAPPERS_H

#include "macos_log.h"

void __wrap_w_macos_set_last_log_timestamp(char * timestamp);

void __wrap_w_macos_set_log_settings(char * settings);

bool __wrap_w_is_macos_sierra();

pid_t __wrap_w_get_first_child(pid_t parent_pid);

void __wrap_w_macos_set_is_valid_data(bool is_valid);

#endif
