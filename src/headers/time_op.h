/*
 * Time operations
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October 4, 2017
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef TIME_OP_H
#define TIME_OP_H


#include <time.h>

#define TIME_LENGTH     64

#ifndef WIN32

void gettime(struct timespec *ts);

// Computes a -= b
void time_sub(struct timespec * a, const struct timespec * b);

#endif // WIN32

char *w_get_timestamp(time_t time);

#endif // TIME_OP_H
