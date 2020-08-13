/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef INTEGRITY_OP_WRAPPERS_H
#define INTEGRITY_OP_WRAPPERS_H

#include "../headers/integrity_op.h"

char * __wrap_dbsync_check_msg(const char * component, dbsync_msg msg, long id, const char * start, const char * top,
                               const char * tail, const char * checksum);

char * __wrap_dbsync_state_msg(const char * component, cJSON * data);

#endif
