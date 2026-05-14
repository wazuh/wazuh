/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WMODULES_WRAPPERS_H
#define WMODULES_WRAPPERS_H

#include <stddef.h>
#include "../../wazuh_modules/wmodules.h"

int __wrap_wm_sendmsg(int usec,
                      int queue,
                      const char *message,
                      const char *locmsg,
                      char loc);

int __wrap_wm_state_io(const char * tag,
                       int op,
                       void *state,
                       size_t size);

int __wrap_wm_validate_command(const char *command,
                               const char *digest,
                               crypto_type ctype);

void expect_wm_validate_command(const char *command,
                                const char *digest,
                                crypto_type ctype,
                                int ret);

#endif
