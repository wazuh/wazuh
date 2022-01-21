/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef LABELS_OP_WRAPPERS_H
#define LABELS_OP_WRAPPERS_H

#include "shared.h"

wlabel_t* __wrap_labels_find(char* agent_id, int* sock);

char* __wrap_labels_get(const wlabel_t* labels, const char* key);

void __wrap_labels_free(wlabel_t *labels);

#endif
