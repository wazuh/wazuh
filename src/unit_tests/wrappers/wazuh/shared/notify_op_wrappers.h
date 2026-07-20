/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32

#ifndef NOTIFY_OP_WRAPPERS_H
#define NOTIFY_OP_WRAPPERS_H

#include "notify_op.h"
#include "shared.h"

int __wrap_wnotify_modify(wnotify_t* notify, int fd, const woperation_t op);

int __wrap_wnotify_add(wnotify_t* notify, int fd, const woperation_t op);

#endif

#endif
