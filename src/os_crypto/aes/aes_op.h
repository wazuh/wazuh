/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* OS_crypto/aes Library
 * APIs for many crypto operations
 */

#ifndef __AES_OP_H
#define __AES_OP_H


#define OS_ENCRYPT      1
#define OS_DECRYPT      0

int encrypt_AES(const unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext);
int decrypt_AES(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *plaintext);
void handleErrors(void);
int OS_AES_Str(const char *input, char *output, const char *charkey,
              long size, short int action) __attribute((nonnull));

#endif

