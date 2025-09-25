/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef BULK_H
#define BULK_H

#include "shared.h"

/**
 * @brief Growable byte buffer.
 */
typedef struct {
    char  *buf;  /**< Pointer to contiguous byte storage (may be NULL). */
    size_t len;  /**< Number of valid bytes currently stored. */
    size_t cap;  /**< Allocated capacity in bytes. */
} bulk_t;

/**
 * @brief Ensure capacity for appending @p add more bytes.
 * @param b   Buffer to grow.
 * @param add Number of additional bytes the caller intends to append.
 */
int bulk_reserve(bulk_t *b, size_t add);

/**
 * @brief Initialize buffer and optionally pre-reserve capacity.
 * @param b        Buffer to initialize.
 * @param cap_hint Optional initial capacity hint (bytes); 0 to skip pre-reserve.
 */
void bulk_init(bulk_t *b, size_t cap_hint);

/**
 * @brief Release buffer memory and reset to empty state.
 * @param b Buffer to free.
 */
void bulk_free(bulk_t *b);

/**
 * @brief Append raw bytes to the end of the buffer.
 * @param b Destination buffer.
 * @param p Source byte range (may be NULL only if @p n is 0).
 * @param n Number of bytes to append.
 */
int bulk_append(bulk_t *b, const void *p, size_t n);

/**
 * @brief Append printf-style formatted text (excluding the trailing NUL).
 * @param b   Destination buffer.
 * @param fmt printf-style format string.
 * @param ... Variadic arguments consumed by @p fmt.
 */
int bulk_append_fmt(bulk_t *b, const char *fmt, ...);

#endif // BULK_H
