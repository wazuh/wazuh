/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "../../os_crypto/aes/aes_op.h"
#include "../../wrappers/common.h"
#include "../headers/shared.h"

typedef unsigned char uchar;

int test_AES()
{
    const char *initialString = "teststring";

    uchar *iv  = (uchar *)"FEDCBA0987654321";
    uchar *key = (uchar *)"1234567890ABCDEF";
    
    const int buffersize = 1024;
    char encryptedBufffer[buffersize];
    char decryptedBufffer[buffersize];

    int encryptedSize = encrypt_AES((uchar*)initialString, (int)strlen(initialString), key, iv, (uchar*)encryptedBufffer);
    
    // AES output string is non readable, we need to decrypt for the assert
    int decryptedSize = decrypt_AES((uchar*)encryptedBufffer, encryptedSize, key, iv, (uchar*)decryptedBufffer);
    
    assert_string_equal(decryptedBufffer, initialString);
    assert_string_equal(decryptedBufffer, initialString);
}

int main(void) 
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_AES),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
