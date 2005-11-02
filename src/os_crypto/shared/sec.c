/*   $OSSEC, sec.c, v0.2, 2005/02/10, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Reads the private keys from the clients
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "shared.h"

#include "headers/sec.h"

#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"


#define KEYSIZE	 72


/* _MemClear v0.1 - Internal use */
void _MemClear(char *id, char *name, char *ip, char *key)
{
	memset(id,'\0', KEYSIZE);
	memset(name,'\0',KEYSIZE);
	memset(key,'\0', KEYSIZE);
	memset(ip,'\0', KEYSIZE);
}

/* _CHash v0.1 -Internal use  */
void _CHash(keystruct *keys, char *id, char *name, char *ip, char *key)
{
	os_md5 filesum1;
	os_md5 filesum2;
    
	char _finalstr[KEYSIZE];
    
    struct sockaddr_in peer;
    
    
	keys->ids = (char **)realloc(keys->ids,
			(keys->keysize+1) * sizeof(char *));
	
    keys->ips = (char **)realloc(keys->ips,
            (keys->keysize+1)* sizeof(char*));

    keys->peer_info = realloc(keys->peer_info,
            (keys->keysize+1) * sizeof(peer));
    
    if(!keys->ids || !keys->ips || !keys->peer_info) 
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
    
	keys->ids[keys->keysize] = strdup(id);
	keys->ips[keys->keysize] = strdup(ip);

    if(!keys->ids[keys->keysize] || !keys->ips[keys->keysize])
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }


	
	/* Generating key */
	/* MD5 from name, id and key */
	OS_MD5_Str(name, filesum1);	
	OS_MD5_Str(id,  filesum2);


	/* Generating new filesum1 */ 
	snprintf(_finalstr, sizeof(_finalstr)-1, "%s%s",filesum1,filesum2);
	
    /* Using just half of the first md5 (user/id) */
    OS_MD5_Str(_finalstr, filesum1);
    filesum1[15] = '\0';	
    filesum1[16] = '\0';
    	
    OS_MD5_Str(key, filesum2);	
	
    
	/* Generating final key */
	memset(_finalstr,'\0', 65);
	snprintf(_finalstr, 49, "%s%s", filesum2, filesum1);

    /* Final key is 48 * 4 = 192bits */


    keys->keys = (char **)realloc(keys->keys,
			(keys->keysize+1)*sizeof(char *));
	if(keys->keys == NULL)
       ErrorExit(MEM_ERROR, ARGV0); 


    keys->keys[keys->keysize]=strdup(_finalstr);
    
    if(keys->keys[keys->keysize] == NULL)
       ErrorExit(MEM_ERROR, ARGV0); 



	/* Cleaning final string from memory */
	memset(_finalstr,'\0', 65);


	/* next */
	keys->keysize++;	
    
	return;
}



/* ReadKeys v0.1: 2005/02/01 */
void ReadKeys(keystruct *keys)
{
    FILE *fp;
    
    char buffer[OS_MAXSTR +1];
    
    char name[KEYSIZE];
    char ip[KEYSIZE];
    char id[KEYSIZE];
    char key[KEYSIZE];
    

    if(File_DateofChange(KEYS_FILE) < 0)
        ErrorExit(NO_AUTHFILE, ARGV0, KEYS_FILE);

    fp = fopen(KEYS_FILE,"r");
    if(!fp)
    {
        /* We can leave from here */
        ErrorExit(FOPEN_ERROR, ARGV0, KEYS_FILE);
    }


    /* Initializing structure */
    keys->ids = NULL;
    keys->keys = NULL;
    keys->ips = NULL;
    keys->keysize = 0;

    _MemClear(id, name, ip, key);

    memset(buffer, '\0', OS_MAXSTR +1);
    
    /* Reading each line.
     * lines are divided on id name ip key
     */
    while(fgets(buffer, OS_MAXSTR, fp) != NULL)
    {
        char *tmp_str;
        char *valid_str;
        if((buffer[0] == '#') || (buffer[0] == ' '))
            continue;

        /* Getting ID */
        valid_str = buffer;
        tmp_str = index(buffer, ' ');
        if(!tmp_str)
        {
            merror(INVALID_KEY, ARGV0, buffer);
            continue;
        }

        *tmp_str = '\0';
        tmp_str++;

        strncpy(id, valid_str, KEYSIZE -1);

        /* Getting name */
        valid_str = tmp_str;
        tmp_str = index(tmp_str, ' ');
        if(!tmp_str)
        {
            merror(INVALID_KEY, ARGV0, buffer);
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(name, valid_str, KEYSIZE -1);
         
        /* Getting ip address */
        valid_str = tmp_str;
        tmp_str = index(tmp_str, ' ');
        if(!tmp_str)
        {
            merror(INVALID_KEY, ARGV0, buffer);
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(ip, valid_str, KEYSIZE -1);
        
        /* Getting key */
        valid_str = tmp_str;
        tmp_str = index(tmp_str, '\n');
        if(tmp_str)
        {
            *tmp_str = '\0';
        }

        strncpy(key, valid_str, KEYSIZE -1);
        
        /* Generating the key hash */
       _CHash(keys, id, name, ip, key);

        /* Clearing the memory */
        _MemClear(id, name, ip, key); 
        
        continue;
    }
    
    fclose(fp);

    /* clear one last time before leaving */
    _MemClear(id,name,ip,key);		
    
    return;
}



/* IsAllowedIP v0.1: 2005/02/09 */
int IsAllowedIP(keystruct *keys, char *srcip)
{
    int i = 0;

    if(srcip == NULL)
        return(-1);
   
    for(i = 0; i < keys->keysize; i++)
    {
        if(strcmp(keys->ips[i],srcip) == 0)
            return(i);
    }
    return(-1);
}



/* CheckSum v0.1: 2005/02/15 
 * Verify the checksum of the message.
 * Also removes the checksum and the random
 * number from it.
 * Returns NULL on error or the message on success.
 */
char *CheckSum(char *msg, int size)
{
    os_md5 recvd_sum;
    os_md5 checksum;

    /* Better way */
    msg++;
    strncpy(recvd_sum,msg,32);
    recvd_sum[32]='\0';

    msg+=32;

    OS_MD5_Str(msg, checksum);
    
    if(strncmp(checksum,recvd_sum,32) != 0)
        return(NULL);
    
    /* Removing ':' */    
    msg++;

    /* Removing random number */
    msg = index(msg, ':');
    if(!msg)
        return(NULL);
    
    /* Removing : after random */
    msg++;

    return(msg);
}



/* ReadSecMSG v0.2: 2005/02/10 */
char *ReadSecMSG(keystruct *keys, char *buffer, char *cleartext, 
                                  int id, int buffer_size)
{
    char *f_msg;
    if(*buffer != ':')
    {
        merror(ENCFORMAT_ERROR, ARGV0, keys->ips[id]);
        return(NULL);
    }

    
    buffer++; /* to next : */
   
   
    if(!OS_BF_Str(buffer, cleartext, keys->keys[id], buffer_size,OS_DECRYPT)) 
    {
        merror(ENCKEY_ERROR, ARGV0, keys->ips[id]);
        return(NULL);
    }

    /* Checking first char -- must be ':' */
    else if(cleartext[0] != ':')
    {
        merror(ENCFORMAT_ERROR, ARGV0, keys->ips[id]);
        return(NULL);
    }
    
    /* Checking checksum -- it also removes the random in there */

    f_msg = CheckSum(cleartext, buffer_size);
    if(f_msg == NULL)
    {
        merror(ENCSUM_ERROR, ARGV0, keys->ips[id]);
        return(NULL);
    }

    return(f_msg);    
}



/* Creat a encrypted message.
 * Returns the size of it
 */
int CreateSecMSG(keystruct *keys, char *msg, char *msg_encrypted,
                                  int id)
{
    int msg_size;
    int final_size;
    int bfsize;
    
    unsigned short int rand0;
    unsigned short int rand1;
    
    char _tmpmsg[OS_MAXSTR +1];
    char _finmsg[OS_MAXSTR +1];
    
    os_md5 md5sum;
    
    msg_size = strlen(msg);
    
    if((msg_size > (OS_MAXSTR - 64))||(msg_size < 1))
    {
        merror(ENCSIZE_ERROR, ARGV0, msg);
        return(0);
    }
    
    /* Random number */
    rand0 = (unsigned short int)rand();
    rand1 = (unsigned short int)rand();

     
    /* Padding the message (needs to be div by 8) */
    bfsize = 8 - (msg_size % 8);
    if(bfsize == 8)
        bfsize = 0;

    _tmpmsg[OS_MAXSTR] = '\0';
    _finmsg[OS_MAXSTR] = '\0';
    msg_encrypted[OS_MAXSTR] = '\0';
    
    snprintf(_tmpmsg, OS_MAXSTR,":%07hu%05hu%0*d:%s",rand1,rand0,bfsize+1,1,msg);

    
    /* Generating md5sum of the unencrypted string */
    OS_MD5_Str(_tmpmsg, md5sum);

    
    /* Generating final msg to be encrypted */
    snprintf(_finmsg, OS_MAXSTR,":%s%s",md5sum,_tmpmsg);

    msg_size = strlen(_finmsg);

    msg_encrypted[0] = ':';
    msg_encrypted++;
    
    /* Encrypting everything */
    OS_BF_Str(_finmsg, msg_encrypted, keys->keys[id], msg_size, OS_ENCRYPT);
    
    msg_encrypted--;

    return(msg_size +1);
}


/* EOF */
