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

#define IDMAXSIZE 8

typedef struct _keystruct
{
    char **ids;
    char **keys;
    char **ips;
    char **name;
    struct sockaddr_in *peer_info;
    FILE **fps;
    unsigned int *global;
    unsigned int *local;
    unsigned int *rcvd;

    int keysize;
}keystruct;

void ReadKeys(keystruct *keys, int just_read);
char *ReadSecMSG(keystruct *keys, char *buffer, char *cleartext, 
                                  int id, int buffer_size);
int CreateSecMSG(keystruct *keys, char *msg, char *msg_encrypted,
                                  int id);
int IsAllowedIP(keystruct *keys, char *srcip);
int IsAllowedID(keystruct *keys, char *id);
void RemoveCounter(char *id);

#endif

/* EOF */
