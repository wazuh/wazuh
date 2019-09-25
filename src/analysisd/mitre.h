/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MITRE_H
#define MITRE_H

#include "shared.h"
#include "os_net/os_net.h"
#include "headers/wazuhdb_op.h"

int mitre_load();
cJSON * mitre_get_attack(const char * mitre_id);

#endif /* MITRE_H */