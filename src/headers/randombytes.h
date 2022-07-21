/*
 * Copyright (C) 2015, Wazuh Inc.
 * Contributed by Jeremy Rossi (@jrossi)
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

void randombytes(void *ptr, size_t length);
void srandom_init(void);
int os_random(void);

#endif /* RANDOMBYTES_H */
