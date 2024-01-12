/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef RUN_REALTIME_WRAPPERS_H
#define RUN_REALTIME_WRAPPERS_H

#include "../../../../config/syscheck-config.h"

int __wrap_realtime_adddir(const char *dir,
                           directory_t *configuration);

int __wrap_realtime_start();

/**
 * @brief This function loads the expect and will_return calls for the wrapper of realtime_adddir
 */
void expect_realtime_adddir_call(const char *path, int ret);

int __wrap_fim_add_inotify_watch(const char *dir,
                                 const directory_t *configuration);

void __wrap_realtime_process();

void __wrap_realtime_sanitize_watch_map();

#endif
