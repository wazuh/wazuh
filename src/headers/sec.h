/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef __SEC_H
#define __SEC_H

#include <time.h>

/* Unique key for each agent */
typedef struct _keyentry {
    time_t rcvd;
    unsigned int local;
    unsigned int keyid;
    unsigned int global;

    char *id;
    char *key;
    char *name;

    os_ip *ip;
    struct sockaddr_in peer_info;
    FILE *fp;
} keyentry;

/* Key storage */
typedef struct _keystore {
    /* Array with all the keys */
    keyentry **keyentries;

    /* Hashes, based on the ID/IP to look up the keys */
    OSHash *keyhash_id;
    OSHash *keyhash_ip;

    /* Total key size */
    unsigned int keysize;

    /* Key file stat */
    time_t file_change;
} keystore;

/** Function prototypes -- key management **/

/* Check if the authentication keys are present */
int OS_CheckKeys(void);

/* Read the keys */
void OS_ReadKeys(keystore *keys) __attribute((nonnull));

/* Free the auth keys */
void OS_FreeKeys(keystore *keys) __attribute((nonnull));

/* Check if key changed */
int OS_CheckUpdateKeys(const keystore *keys) __attribute((nonnull));

/* Update the keys if they changed on the system */
int OS_UpdateKeys(keystore *keys) __attribute((nonnull));

/* Start counter for all agents */
void OS_StartCounter(keystore *keys) __attribute((nonnull));

/* Remove counter for id */
void OS_RemoveCounter(const char *id) __attribute((nonnull));


/** Function prototypes -- agent authorization **/

/* Check if the IP is allowed */
int OS_IsAllowedIP(keystore *keys, const char *srcip) __attribute((nonnull(1)));

/* Check if the ID is allowed */
int OS_IsAllowedID(keystore *keys, const char *id) __attribute((nonnull(1)));

/* Check if the name is valid */
int OS_IsAllowedName(const keystore *keys, const char *name) __attribute((nonnull));

/* Check if the id is valid and dynamic */
int OS_IsAllowedDynamicID(keystore *keys, const char *id, const char *srcip) __attribute((nonnull(1)));


/** Function prototypes -- send/recv messages **/

/* Decrypt and decompress a remote message */
char *ReadSecMSG(keystore *keys, char *buffer, char *cleartext,
                 int id, unsigned int buffer_size) __attribute((nonnull));

/* Create an OSSEC message (encrypt and compress) */
size_t CreateSecMSG(const keystore *keys, const char *msg, char *msg_encrypted, unsigned int id) __attribute((nonnull));


/** Remote IDs directories and internal definitions */
#ifndef WIN32
#define RIDS_DIR        "/queue/rids"
#else
#define RIDS_DIR        "rids"
#endif

#define SENDER_COUNTER  "sender_counter"
#define KEYSIZE         128

#endif /* __SEC_H */

