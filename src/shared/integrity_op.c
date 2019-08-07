/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * July 12, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "integrity_op.h"


int generate_integrity(OSHash * hashdata, integrity * integrity_checksums) {
    OSHashNode * current_node = NULL;
    char * checksum;
    int hash_row_cbrt;
    unsigned int neb0 = 0;
    unsigned int neb1 = 0;
    unsigned int neb2 = 0;
    unsigned int l0;
    unsigned int l1;
    unsigned int l2;
    unsigned int modl1;
    unsigned int modl2;
    unsigned int row;
    int tel1 = 0;
    int tel2 = 0;
    SHA_CTX * l0sha1;
    SHA_CTX * l1sha1;
    SHA_CTX * l2sha1;
    os_sha1 * hash0;
    os_sha1 * hash1;
    os_sha1 * hash2;

    // TODO: Chech hash table size cant be less than 8?
    if (hashdata->rows < 8) {
        mwarn("Invalid hash table size to generate integrity checksum: %d",
                hashdata->rows);
        return (-1);
    }

    os_calloc(1, sizeof(SHA_CTX), l0sha1);
    os_calloc(1, sizeof(SHA_CTX), l1sha1);
    os_calloc(1, sizeof(SHA_CTX), l2sha1);

    os_calloc(1, sizeof(os_sha1), hash0);
    os_calloc(1, sizeof(os_sha1), hash1);
    os_calloc(1, sizeof(os_sha1), hash2);

    hash_row_cbrt = cbrt(hashdata->rows);
    l0 = hashdata->rows;
    l1 = hash_row_cbrt * hash_row_cbrt;
    l2 = hash_row_cbrt;

    modl1 = l0 % l1;
    modl2 = l1 % l2;

    integrity_hash(l0sha1, NULL, NULL, 0);
    integrity_hash(l1sha1, NULL, NULL, 0);
    integrity_hash(l2sha1, NULL, NULL, 0);

    for (row = 0; row < hashdata->rows; row++) {
        current_node = hashdata->table[row];

        do {
            checksum = NULL;
            if (current_node) {
                checksum = integrity_checksums->get_checksum(current_node->data);
            } else {
                os_calloc(1, sizeof(os_sha1), checksum);
            }

            // Update hash level 0
            integrity_hash(l0sha1, NULL, checksum, 1);
            minfo("Updating hash0 '%s'", checksum);
            os_free(checksum);

            if(current_node) {
                minfo("%s", current_node->key);
                current_node = current_node->next;
            }

        } while(current_node);

        // Level 0 hash finished
        integrity_hash(l0sha1, hash0, NULL, 2);
        save_integrity(0, row, *hash0, integrity_checksums);
        minfo("hash0: %s", *hash0);
        minfo("L0B%d~~~~~~~~~~~~~~~", row);
        neb0++;
        // Reset for next block of level 0
        integrity_hash(l0sha1, NULL, NULL, 0);


        // Check elements L0
        if (neb0 >= (l0 / l1) + (modl1 ? 1 : 0)) {
            integrity_hash(l1sha1, NULL, (char*)hash0, 1);
            minfo("Updating hash1 '%s'", (char*)hash0);
            // Level 1 hash finished
            integrity_hash(l1sha1, hash1, NULL, 2);
            save_integrity(1, tel1, *hash1, integrity_checksums);
            minfo("hash1: %s", *hash1);
            minfo("L1B%d~~~~~~~~~~~~~~~", tel1);
            neb0 = 0;
            neb1++;
            tel1++;
            modl1 = (modl1 ? modl1-1 : 0);
            // Reset for next block of level 1
            integrity_hash(l1sha1, NULL, NULL, 0);

            // Check elements L1
            if (neb1 >= (l1 / l2) + (modl2 ? 1 : 0)) {
                integrity_hash(l2sha1, NULL, (char*)hash1, 1);
                minfo("Updating hash2 '%s'", (char*)hash1);
                // Level 2 hash finished
                integrity_hash(l2sha1, hash2, NULL, 2);
                save_integrity(2, tel2, *hash2, integrity_checksums);
                minfo("hash2: %s", *hash2);
                minfo("L2B%d~~~~~~~~~~~~~~~", tel2);
                neb1 = 0;
                neb2++;
                tel2++;
                modl2 = (modl2 ? modl2-1 : 0);
                // Reset for next block of level 2
                integrity_hash(l2sha1, NULL, NULL, 0);
            } else {
                // Update hash level 2
                integrity_hash(l2sha1, NULL, (char*)hash1, 1);
                minfo("Updating hash2 '%s'", (char*)hash1);
            }
        } else {
            // Update hash level 1
            integrity_hash(l1sha1, NULL, (char*)hash0, 1);
            minfo("Updating hash1 '%s'", (char*)hash0);
        }
    }

    return 0;
}


int integrity_hash(SHA_CTX * sha1, os_sha1 * hash, char * checksum, int ac) {
    unsigned char dig[SHA_DIGEST_LENGTH];
    size_t n;

    switch(ac) {
    case 0: // Init

        SHA1_Init(sha1);

        break;
    case 1: // Update

        if (checksum) {
            n = strlen(checksum);
            SHA1_Update(sha1, checksum, n);
        }

        break;
    case 2: // Final

        if (hash) {
            SHA1_Final(&(dig[0]), sha1);
            memset(*hash, 0, 65);

            for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
                snprintf((char*)hash + (n * 2), 3, "%02x", dig[n]);
            }
        }

        break;
    }

    return (0);
}


integrity * initialize_integrity (int rows, char * (checksum_func)(void*)) {
    integrity * integrity_checksums;
    int hash_row_cbrt;
    unsigned int l0;
    unsigned int l1;
    unsigned int l2;
    unsigned int item;

    hash_row_cbrt = cbrt(rows);
    l0 = rows;
    l1 = hash_row_cbrt * hash_row_cbrt;
    l2 = hash_row_cbrt;

    os_calloc(1, sizeof(integrity), integrity_checksums);

    os_calloc(l0, sizeof(integrity_block), integrity_checksums->level0);
    os_calloc(l1, sizeof(integrity_block), integrity_checksums->level1);
    os_calloc(l2, sizeof(integrity_block), integrity_checksums->level2);

    for(item = 0; item < l0; item++) {
        os_calloc(OS_SIZE_16, sizeof(char), integrity_checksums->level0[item].block_name);
    }

    for(item = 0; item < l1; item++) {
        os_calloc(OS_SIZE_16, sizeof(char), integrity_checksums->level1[item].block_name);
    }

    for(item = 0; item < l2; item++) {
        os_calloc(OS_SIZE_16, sizeof(char), integrity_checksums->level2[item].block_name);
    }

    integrity_checksums->items_l0 = 0;
    integrity_checksums->items_l1 = 0;
    integrity_checksums->items_l2 = 0;

    // Set function to calculate checksums
    integrity_checksums->get_checksum = checksum_func;

    return integrity_checksums;
}


int save_integrity(int level, int block, os_sha1 hash, integrity * integrity_checksums) {

    switch(level) {
    case 0:
        snprintf(integrity_checksums->level0[block].block_name, OS_SIZE_16, "L%dB%d", level, block);
        os_strdup(hash, integrity_checksums->level0[block].checksum);
        integrity_checksums->items_l0++;
        break;
    case 1:
        snprintf(integrity_checksums->level1[block].block_name, OS_SIZE_16, "L%dB%d", level, block);
        os_strdup(hash, integrity_checksums->level1[block].checksum);
        integrity_checksums->items_l1++;
        break;
    case 2:
        snprintf(integrity_checksums->level2[block].block_name, OS_SIZE_16, "L%dB%d", level, block);
        os_strdup(hash, integrity_checksums->level2[block].checksum);
        integrity_checksums->items_l2++;
        break;
    }

    return 0;
}


void print_integrity(integrity * integrity_checksums) {
    int i;

    minfo("level 0: %d", integrity_checksums->items_l0);
    for (i = 0; i < integrity_checksums->items_l0; i++) {
        minfo("%s->%s", integrity_checksums->level0[i].block_name, integrity_checksums->level0[i].checksum);
    }
    minfo("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    minfo("level 1: %d", integrity_checksums->items_l1);
    for (i = 0; i < integrity_checksums->items_l1; i++) {
        minfo("%s->%s", integrity_checksums->level1[i].block_name, integrity_checksums->level1[i].checksum);
    }
    minfo("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    minfo("level 2: %d", integrity_checksums->items_l2);
    for (i = 0; i < integrity_checksums->items_l2; i++) {
        minfo("%s->%s", integrity_checksums->level2[i].block_name, integrity_checksums->level2[i].checksum);
    }
    minfo("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}
