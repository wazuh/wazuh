/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "headers/shared.h"
#include "headers/sec.h"
#include "msgs_wrappers.h"

size_t __wrap_CreateSecMSG(__attribute__((unused)) keystore *keys, const char *msg, size_t msg_length, char *msg_encrypted, unsigned int id) {
    check_expected(msg);
    check_expected(msg_length);
    check_expected(id);

    size_t size = mock();

    strncpy(msg_encrypted, mock_type(char*), size);

    return size;
}

int __wrap_ReadSecMSG(keystore *keys, char *buffer, char *cleartext, int id, unsigned int buffer_size, size_t *final_size, const char *srcip, char **output) {
    check_expected(buffer);
    *final_size = (int)mock();
    *output = (char*)mock_ptr_type(char *);
    return (int)mock();
}
