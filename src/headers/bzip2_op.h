/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

int bzip2_compress(const char *file, const char *filebz2);
int bzip2_uncompress(const char *file, const char *filebz2);

#endif /* BZIP2_OP_H */
