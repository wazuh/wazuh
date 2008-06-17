/* @(#) $Id$ */

/* Copyright (C) 2004-2008 Third Brigade, Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __MEM_H

#define __MEM_H

#include "shared.h"

void os_FreeArray(char *ch1, char **ch2);
int os_IsStrOnArray(char *str, char **array);
char *os_LoadString(char *at, char *str);

#endif
