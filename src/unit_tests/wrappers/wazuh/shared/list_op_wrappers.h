/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef LIST_OP_WRAPPERS_H
#define LIST_OP_WRAPPERS_H

#include "shared.h"

void *__wrap_OSList_AddData(__attribute__((unused))OSList *list, __attribute__((unused))void *data);

#endif // LIST_OP_WRAPPERS_H