/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MSGS_WRAPPERS_H
#define MSGS_WRAPPERS_H

#include <sys/types.h>

size_t __wrap_CreateSecMSG(__attribute__((unused)) keystore *keys, const char *msg, size_t msg_length, char *msg_encrypted, unsigned int id);
int __wrap_ReadSecMSG(keystore *keys, char *buffer, __attribute__((unused)) char *cleartext, int id, __attribute__((unused)) unsigned int buffer_size, size_t *final_size, const char *srcip, char **output);

#endif
