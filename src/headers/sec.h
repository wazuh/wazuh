/*   $OSSEC, sec.h, v0.1, 2005/01/28, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
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
    int *rcvd;

    int keysize;
}keystruct;

void ReadKeys(keystruct *keys);
char *ReadSecMSG(keystruct *keys, char *buffer, char *cleartext, 
                                  int id, int buffer_size);
int CreateSecMSG(keystruct *keys, char *msg, char *msg_encrypted,
                                  int id);
int IsAllowedIP(keystruct *keys, char *srcip);
int IsAllowedID(keystruct *keys, char *id);
void RemoveCounter(char *id);

#endif

/* EOF */
