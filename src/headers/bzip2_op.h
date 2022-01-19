/*
 * Copyright (C) 2015, Wazuh Inc.
 * April, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BZIP2_OP_H
#define BZIP2_OP_H

#include <bzlib.h>

#define BZIP2_BUFFER_SIZE 4096

/**
 * @brief bzpi2 library, function to compress
 *
 * @param file File path to compress
 * @param filebz2 File name compressed
 *
 * @retval 0 on success
 * @retval -1 on error
 */
int bzip2_compress(const char *file, const char *filebz2);

/**
 * @brief bzpi2 library, function to uncompress
 *
 * @param filebz2 File path to uncompress
 * @param file File name uncompressed
 *
 * @retval 0 on success
 * @retval -1 on error
 */
int bzip2_uncompress(const char *filebz2, const char *file);

#endif /* BZIP2_OP_H */
