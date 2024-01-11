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
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"
#include "keys_wrappers.h"

int __wrap_OS_IsAllowedDynamicID(__attribute__((unused)) keystore *keys, const char *id, const char *srcip) {
    check_expected(id);
    check_expected(srcip);

    return mock();
}

int __wrap_OS_DeleteSocket(__attribute__((unused)) keystore * keys, int sock) {
    check_expected(sock);

    return mock();
}

int __wrap_OS_IsAllowedIP(__attribute__((unused)) keystore *keys, const char *srcip) {
    check_expected(srcip);

    return mock();
}

int __wrap_OS_IsAllowedID(__attribute__((unused)) keystore *keys, const char *id) {
    check_expected(id);

    return mock();
}

keyentry * __wrap_OS_DupKeyEntry(const keyentry * key) {
    check_expected(key);

    return mock_type(keyentry *);
}

int __wrap_OS_AddSocket(keystore * keys, unsigned int i, int sock) {
    check_expected(keys);
    check_expected(i);
    check_expected(sock);

    return mock();
}

void __wrap_OS_FreeKey(keyentry *key) {
    check_expected(key);

    return;
}
