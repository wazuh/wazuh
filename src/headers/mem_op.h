/* @(#) $Id: ./src/headers/mem_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __MEM_H

#define __MEM_H

void **os_AddPtArray(void *pt, void **array);
char **os_AddStrArray(char *str, char **array);
void os_FreeArray(char *ch1, char **ch2);
int os_IsStrOnArray(char *str, char **array);
char *os_LoadString(char *at, char *str);

#endif
