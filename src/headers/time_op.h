/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file time_op.h
 * @brief Time operations header file
 * @author Vikman Fernandez-Castro
 * @author Jose Rafael Cenit
 * @author Pablo Navarro
 * @date October 4, 2017
 */

#ifndef TIME_OP_H
#define TIME_OP_H

#ifndef WIN32

#include <time.h>

/**
 * @brief Get the current calendar time
 *
 * @param ts Pointer to a timespec structure
 */
void gettime(struct timespec *ts);

/**
 * @brief Compute time substraction "a - b"
 *
 * @param a Minuend
 * @param b Subtrahend
 */
void time_sub(struct timespec * a, const struct timespec * b);

/**
 * @brief Get the time difference
 *
 * @param a Timestamp before
 * @param b Timestamp after
 * @return Time elapsed between a and b (in seconds)
 */
double time_diff(const struct timespec * a, const struct timespec * b);

#else

/**
 * @brief Get the epoch time
 *
 * @return Number of seconds since the epoch
 */
long long int get_windows_time_epoch();

/**
 * @brief Get the epoch time from a FILETIME object
 *
 * @param ft
 * @return Number of seconds since the epoch
 */
long long int get_windows_file_time_epoch(FILETIME ft);

#endif

#endif // TIME_OP_H
