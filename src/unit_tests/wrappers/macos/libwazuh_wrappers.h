/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STDIO_WRAPPERS_LIBWAZUH_H
#define STDIO_WRAPPERS_LIBWAZUH_H


#undef mterror
#define mterror wrap_mterror

void wrap_mterror(const char *tag, const char *msg, ...);

#endif