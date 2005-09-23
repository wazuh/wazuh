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
    int keysize;
}keystruct;

void ReadKeys(keystruct *keys);
char *ReadSecMSG(keystruct *keys, char *srcip, char *buffer);
char *CreateSecMSG(keystruct *keys,char *msg, int id, int *msgsize, 
	unsigned short int rand0);
int CheckAllowedIP(keystruct *keys, char *srcip, char *id);
int CheckSum(char *msg, int size);

#endif

/* EOF */
