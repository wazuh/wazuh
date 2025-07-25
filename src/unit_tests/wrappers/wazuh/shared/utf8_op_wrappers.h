/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef UTF8_OP_WRAPPERS_H
#define UTF8_OP_WRAPPERS_H

#include "../../../../headers/utf8_op.h"

bool __wrap_w_utf8_valid(const char* string);

#endif
