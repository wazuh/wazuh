/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef STRING_OP_WRAPPERS_h
#define STRING_OP_WRAPPERS_h

#include <string.h>

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>

char *__wrap_convert_windows_string(LPCWSTR string);
#endif

int __wrap_wstr_end(char *str, const char *str_end);

char *__wrap_wstr_escape_json(const char * string);

char *__wrap_wstr_replace(const char * string, const char * search, const char * replace);

void __wrap_wstr_split(char *str, char *delim, char *replace_delim, int occurrences, char ***splitted_str);

#endif
