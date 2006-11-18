/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __SEC_H
#define __SEC_H


/* Key structure. */
typedef struct _keystruct
{
    char **ids;
    char **keys;
    os_ip **ips;
    char **name;
    struct sockaddr_in *peer_info;
    FILE **fps;
    unsigned int *global;
    unsigned int *local;
    unsigned int *rcvd;

    int keysize;
}keystruct;

/* Read the keys */
void ReadKeys(keystruct *keys, int just_read);

/* Decrypt and decompress a ossec message. */
char *ReadSecMSG(keystruct *keys, char *buffer, char *cleartext, 
                                  int id, int buffer_size);

/* Creates an ossec message (encrypts and compress) */
int CreateSecMSG(keystruct *keys, char *msg, char *msg_encrypted,
                                  int id);

/* Checks if the ip is allowed */
int IsAllowedIP(keystruct *keys, char *srcip);

/* Checks if the id is allowed */
int IsAllowedID(keystruct *keys, char *id);

/* Checks for a valid name */
int IsAllowedName(keystruct *keys, char *name);

/* Check if the id is valid and dynamic */
int IsAllowedDynamicID(keystruct *keys, char *id, char *srcip);

/* Remove counter for id. */
void RemoveCounter(char *id);

#endif

/* EOF */
