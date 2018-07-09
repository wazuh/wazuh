/*
 * Contributed by Jeremy Rossi (@jrossi)
 * Maintained by Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __RANDOMBYTES_H
#define __RANDOMBYTES_H

void randombytes(void *ptr, size_t length);
void srandom_init(void);
int os_random(void);

#endif
