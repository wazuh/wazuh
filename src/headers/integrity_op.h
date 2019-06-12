/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * July 12, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __INTEGRITY_H
#define __INTEGRITY_H

#include <openssl/sha.h>
#include <math.h>
#include "shared.h"
#include "hash_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "debug_op.h"


typedef struct integrity {
    struct integrity_block * level0;
    int items_l0;
    struct integrity_block * level1;
    int items_l1;
    struct integrity_block * level2;
    int items_l2;

    char * (*get_checksum)(void *data);
} integrity;

typedef struct integrity_block {
    char * block_name;
    char * checksum;
} integrity_block;


int generate_integrity (OSHash * hashdata, integrity * integrity_checksums);

int integrity_hash (SHA_CTX * sha1, os_sha1 * hash, char * checksum, int action);

integrity * initialize_integrity (int rows, char * (*checksum_func)(void*));

int save_integrity (int level, int block, os_sha1 hash, integrity * integrity_checksums);

void print_integrity();


#endif /* __INTEGRITY_H */