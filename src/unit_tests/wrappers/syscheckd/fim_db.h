/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef UNIT_TEST_WRAPPERS_FIM_DB
#define UNIT_TEST_WRAPPERS_FIM_DB

#include <stdio.h>

#ifdef WIN32
#include <windows.h>

VOID wrap_fim_db_Sleep (DWORD dwMilliseconds);
#endif

int wrap_fprintf(FILE * __restrict__ _File,const char * __restrict__ _Format,...);

extern int test_mode;

#endif
