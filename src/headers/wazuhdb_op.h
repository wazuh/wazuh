/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 15, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_net/os_net.h"


typedef enum wdbc_result { WDBC_OK, WDBC_ERROR, WDBC_IGNORE, WDBC_UNKNOWN } wdbc_result;

int wdbc_connect();
int wdbc_query(const int sock, const char *query, char *response, const int len);
int wdbc_query_ex(int *sock, const char *query, char *response, const int len);
int wdbc_parse_result(char *result, char **payload);
