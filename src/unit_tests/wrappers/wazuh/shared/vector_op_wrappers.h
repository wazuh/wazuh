/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef VECTOR_OP_WRAPPERS_H
#define VECTOR_OP_WRAPPERS_H

#include "syscheckd/syscheck.h"

int __wrap_W_Vector_insert_unique(W_Vector *v, const char *element);

int __wrap_W_Vector_length(W_Vector *v);

#endif
