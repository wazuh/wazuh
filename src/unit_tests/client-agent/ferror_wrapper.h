/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef FERROR_WRAPPER_H
#define FERROR_WRAPPER_H

#include <stdio.h>

int __wrap_ferror(FILE *_File);
void expect_ferror(FILE *_File, int ret);

#endif /* FERROR_WRAPPER_H */
