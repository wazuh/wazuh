/* @(#) $Id: ./src/headers/sec.h, 2011/09/08 dcid Exp $
 */

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


/* Unique key for each agent. */
typedef struct _keyentry
{
    unsigned int rcvd;
    unsigned int local;
    unsigned int keyid;
    unsigned int global;

    char *id;
    char *key;
    char *name;

    os_ip *ip;
    struct sockaddr_in peer_info;
    FILE *fp;
}keyentry;


/* Key storage. */
typedef struct _keystore
{
    /* Array with all the keys */
    keyentry **keyentries;


    /* Hashes, based on the id/ip to lookup the keys. */
    void *keyhash_id;
    void *keyhash_ip;


    /* Total key size */
    int keysize;

    /* Key file stat */
    int file_change;
}keystore;



/** Function prototypes -- key management **/

/* Checks if the authentication keys are present */
int OS_CheckKeys();

/* Read the keys */
void OS_ReadKeys(keystore *keys);

/* Frees the auth keys. */
void OS_FreeKeys(keystore *keys);

/* Checks if key changed. */
int OS_CheckUpdateKeys(const keystore *keys);

/* Update the keys if they changed on the system. */
int OS_UpdateKeys(keystore *keys);


/* Starts counter for all agents */
void OS_StartCounter(keystore *keys);

/* Remove counter for id. */
void OS_RemoveCounter(const char *id);


/** Function prototypes -- agent authorization **/

/* Checks if the ip is allowed */
int OS_IsAllowedIP(keystore *keys, char *srcip);

/* Checks if the id is allowed */
int OS_IsAllowedID(keystore *keys, char *id);

/* Checks if name is valid */
int OS_IsAllowedName(const keystore *keys, const char *name);

/* Check if the id is valid and dynamic */
int OS_IsAllowedDynamicID(keystore *keys, char *id, char *srcip);



/** Function prototypes -- send/recv messages **/

/* Decrypt and decompress a remote message. */
char *ReadSecMSG(keystore *keys, char *buffer, char *cleartext,
                 int id, int buffer_size);

/* Creates an ossec message (encrypts and compress) */
int CreateSecMSG(const keystore *keys, const char *msg, char *msg_encrypted, int id);




/** Remote IDs directories and internal definitions */
#ifndef WIN32
    #define RIDS_DIR        "/queue/rids"
#else
    #define RIDS_DIR        "rids"
#endif

#define SENDER_COUNTER  "sender_counter"
#define KEYSIZE         128


#endif

/* EOF */
