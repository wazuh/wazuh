/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file time_op.h
 * @brief Time operations header file
 * @date October 4, 2017
 */

#ifndef TIME_OP_H
#define TIME_OP_H

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

/**
 * @brief Get the current calendar time
 *
 * @param ts Pointer to a timespec structure
 */

#define TIME_LENGTH     OS_SIZE_128

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

char *w_get_timestamp(const time_t time);

/**
 * @brief Takes sleeps of 1 second until the input time is reached
 *
 * @param time time until which the thread will sleep
 * */
void w_sleep_until(time_t abs_time);

/**
* @brief Sleep function for Windows and Unix (milliseconds)
*
* @param ms sleep time in miliseconds
*/
void w_time_delay(unsigned long int ms);

#ifdef WIN32

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

/**
 * @brief Function to check if a year is a leap year or not.
 *
 * @param year Year to check.
 * @return Boolean indicating whether the year is leap.
 */
bool is_leap_year(int year);

/**
 * @brief Function to get the current UTC time in ISO8601 format.
 *
 * @param buffer Buffer to store the time.
 * @param size Size of the buffer.
 */
void get_iso8601_utc_time(char *buffer, size_t size);

#endif // TIME_OP_H
