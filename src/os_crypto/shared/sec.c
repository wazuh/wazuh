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



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "headers/defs.h"
#include "headers/file_op.h"
#include "headers/debug_op.h"

#include "headers/sec.h"

#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"

#define NAMESIZE 33
#define KEYSIZE	 65
#define IPSIZE	 17


/* _MemClear v0.1 - Internal use */
void _MemClear(char *id, char *name, char *ip, char *key)
{
	memset(id,'\0', IDMAXSIZE);
	memset(name,'\0',NAMESIZE);
	memset(key,'\0', KEYSIZE);
	memset(ip,'\0', IPSIZE);
}

/* _CHash v0.1 -Internal use  */
void _CHash(keystruct *keys, char *id, char *name, char *ip, char *key)
{
	os_md5 filesum1;
	os_md5 filesum2;
    
	char _finalstr[65];
	int _fsize = 0;
	int _idsize = 0;
	int _ipsize = 0;
	
	/* Getting ID */
	_idsize = strlen(id)+1;
	keys->ids = (char **)realloc(keys->ids,
			(keys->keysize+1)*sizeof(char *));	
	if(keys->ids == NULL)
	   ErrorExit("Memory error (realloc 1) while reading private keys");
	
	keys->ids[keys->keysize]=(char *)calloc(_idsize,sizeof(char));
	if(keys->ids[keys->keysize] == NULL)
	   ErrorExit("Memory error (calloc) while reading private keys");

	strncpy(keys->ids[keys->keysize],id,_idsize-1);
      
	/* Getting IP */
	_ipsize=strlen(ip)+1;
	keys->ips = (char **)realloc(keys->ips,
			(keys->keysize+1)* sizeof(char*));
	if(keys->ips == NULL)
	   ErrorExit("Memory error (realloc ips) while reading priv keys");
	
	keys->ips[keys->keysize]=(char*)calloc(_ipsize,sizeof(char));
	if(keys->ips[keys->keysize] == NULL)
	   ErrorExit("Memory error (calloc ips) while reading priv keys");
	strncpy(keys->ips[keys->keysize],ip,_ipsize-1);
	
	
	/* Generating key */
	/* MD5 from name and key */
	OS_MD5_Str(name, filesum1);	
	OS_MD5_Str(key, filesum2);

	/* Cleaning final str */
	memset(_finalstr,'\0', 65);

	/* Generating new filesum1 */ 
	snprintf(_finalstr,64,"%s%s",filesum1,filesum2);
	
    OS_MD5_Str(_finalstr, filesum1);	
	
	/* Generating final key */
	memset(_finalstr,'\0', 65);
	snprintf(_finalstr,64,"%s%s",filesum1,filesum2);

	/* Final size */
	_fsize=strlen(_finalstr)+1;

    keys->keys = (char **)realloc(keys->keys,
			(keys->keysize+1)*sizeof(char *));
	if(keys->keys == NULL)
	   ErrorExit("Memory error (realloc) while reading private keys!\n");

    keys->keys[keys->keysize]=(char *)calloc(_fsize,sizeof(char));
    
    if(keys->keys[keys->keysize] == NULL)
	   ErrorExit("Memory error (calloc) while reading private keys!\n");

	strncpy(keys->keys[keys->keysize],_finalstr,_fsize-1);

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
    
    char c;
    
    char name[NAMESIZE];
    char ip[IPSIZE];
    char id[IDMAXSIZE];
    char key[KEYSIZE];
    
    int _pos=0,j=0,_ig=0;

    if(File_DateofChange(KEYS_FILE) < 0)
        ErrorExit("ossec-remoted: Keys file %s does not exist. No secure "
                  "communication can be established. Exiting...",
                  KEYS_FILE);

    fp = fopen(KEYS_FILE,"r");
    if(!fp)
    {
        /* We can leave from here */
        merror("readkeys: Impossible to open the keys file");
        exit(1);
    }

    /* Initializing structure */
    keys->ids=NULL;
    keys->keys=NULL;
    keys->ips=NULL;
    keys->keysize=0;

    _MemClear(id,name,ip,key);

    while((c = fgetc(fp)) != EOF)
    {
        if( c == '#')
            _ig=1;
            
        if(_ig == 1 && c != '\n')
            continue;
        else
            _ig=0;

        if((_pos == 0) && (j >=7 || c == ' '))
        {
            id[j]='\0';
            _pos++;
            j=0;
            continue;
        }
        else if(_pos == 0 && j < 7)
        {
            id[j]=c;
            j++;
            continue;
        }
        else if((_pos == 1) && (j >= 31 || c == ' '))
        {
            name[j]='\0';
            _pos++;
            j=0;
            continue;
        }
        else if(_pos == 1 && j < 31)
        {
            name[j]=c;
            j++;
            continue;
        }
        else if((_pos == 2) && (j >= 31 || c == ' '))
        {
            ip[j]='\0';
            _pos++;
            j=0;
            continue;
        }
        else if(_pos == 2 && j< 31)
        {
            ip[j]=c;
            j++;
            continue;
        }
        else if((_pos == 3) && (j >= 64 || c == '\n'))
        {
            key[j]='\0';
            _pos=0;	
            j=0;
            /* Generate the key hash and clear the key from the memory */
            _CHash(keys,id,name,ip,key);
            _MemClear(id,name,ip,key);
            continue;
        }
        else if(_pos == 3 && j < 65)
        {
            key[j]=c;
            j++;
            continue;
        }
    }
    
    fclose(fp);

    /* clear one last time before leaving */
    _MemClear(id,name,ip,key);		
    return;
}


/* CheckAllowedIP v0.1: 2005/02/09 */
int CheckAllowedIP(keystruct *keys, char *srcip, char *id)
{
    int i = 0;

    if(srcip == NULL)
        return(-1);
   
    for(i=0;i<keys->keysize;i++)
    {
        if(id != NULL)
        {
            if(strcmp(keys->ids[i],id) != 0)
                continue;
        }
        
        if(strcmp(keys->ips[i],srcip) == 0)
            return(i);
    }
    return(-1);
}


/* CheckSum v0.1: 2005/02/15 
 * Will received the message, retrieve
 * the checksum from it, generate a new checksum
 * from the rest of the message and compare if
 * they match. Return 0 if they match, -1 otherwise.
 */
int CheckSum(char *msg, int size)
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
        return(-1);
        
    return(0);
}


/* ReadSecMSG v0.2: 2005/02/10 */
char *ReadSecMSG(keystruct *keys, char *srcip, char *buffer)
{
    int i=0, _key=0;
    
    long int _rsize=0;

    char *clear_msg = NULL;
    char *id = NULL;    


    if(*buffer != ':')
    {
        merror("(ReadSecMSG): Bad encrypted message(bad [0])");
        return(NULL);
    }

    /* Message:
     * :id:size:msg
     */
    buffer++; /* to next : */
   
    /** Getting id **/ 
    id = buffer;
    
    i = 0;
    while(*buffer != ':')
    {
        if(i >= 8)
        {
            merror("(ReadSecMSG): Bad encrypted message(size 1)");
        }
        
        buffer++;
        i++;
    }
    if(i == 0)
    {
        merror("(ReadSecMSG): Bad encrypted message(size 0)");
    }
    
    id[i] = '\0';

    /* Checking if the id/ip key pair exist */
    _key = CheckAllowedIP(keys,srcip,id);

    if(_key == -1)
    {
        merror("(SecMsg): IP address \"%s\" not allowed.",srcip);
        return(NULL);
    }
                                                                                                    
    /** Getting size **/
    buffer++; /* Jumping to next : */
    i = 0;
    _rsize = atoi(buffer);
    if((_rsize <= 0) || (_rsize >= OS_MAXSTR))
    {
        merror("encrypt-handler: Bad encrypted message (wrong size)");
        return(NULL);
    }
    while(*buffer != ':')
    {
        if(i > 5)
        {
            merror("encrypt-handler: Bad encrypted message (wrong size i)");
            return(NULL);
        }
        i++;
        buffer++;
    }
    if(i == 0)
    {
        merror("encrypt-handler: Bad encrypted message (wrong size 2)");
        return(NULL);
    }
    
    buffer++; /* Buffer is now :, moving to next */
   
    clear_msg = OS_BF_Str(buffer,keys->keys[_key],_rsize,OS_DECRYPT); 

    /* checking for return */
    if(clear_msg == NULL)
    {
        merror("(SecMsg): Bad encrypted message (wrong key)");
        return(NULL);
    }

    /* Checking first char -- must be ':' */
    else if(clear_msg[0] != ':')
    {
        merror("(SecMsg): Bad encrypted message (wrong start)");
    }
    
    /* Checking checksum */
    if(CheckSum(clear_msg,_rsize) < 0)
    {
        merror("(SecMsg): Bad msg checksum");
        free(clear_msg);
        return(NULL);
    }

    return(clear_msg);    
}

/* Createh a encrypted message */
char *CreateSecMSG(keystruct *keys, char *msg, int id, int *msgsize, 
		                            unsigned short int rand0)
{
    register int i=0,j=0;

    unsigned short int rand1;

    int _msize = strlen(msg);
    int _mtotalsize = 0;
    int _bfsize =0 ; /* Must be x % 8 = 0 */

    char _msizechar[6];
    char _tmpmsg[_msize+24];
    char _finmsg[_msize+57];

    char *_crypt_msg = NULL;
    char *msg_encrypted = NULL;

    os_md5 md5sum;

    /* Avoiding any possible message overflow */
    if(_msize >= (OS_MAXSTR - 58))
    {
        merror("(CreateSecMSG): Overflow attempt");
        return(NULL);
    }

    if(_msize <= 16)
    {
        merror("(CreateSecMSG): Small msg, possible craft");
        return(NULL);
    }


    /* rand1  */
    rand1 = (unsigned short int)rand();

    /* Well, well... after two years without looking at this
     * code I have no idea what it does anymore (and why I did this
     * way.. XXX to be re-examined and possible re-implemented later
     * 2005-03
     */
     
    /* Padding the message (needs to be div by 8 */
    _bfsize = 8 - (_msize % 8);
    if(_bfsize == 8)
        _bfsize=0;

    memset(_tmpmsg,'\0',_msize+24);
    memset(_finmsg,'\0',_msize+57);

    snprintf(_tmpmsg,_msize+24,":%07hu%05hu%0*d:%s",rand1,rand0,_bfsize+1,1,msg);

    /* Generating md5sum of the unencrypted string */
    OS_MD5_Str(_tmpmsg, md5sum);

    /* Generating final msg to be encrypted */
    snprintf(_finmsg,_msize+57,":%s%s",md5sum,_tmpmsg);

    memset(_tmpmsg,'\0',_msize+24);

    _msize = strlen(_finmsg);

    /* Encrypting everything */
    msg_encrypted = OS_BF_Str(_finmsg, keys->keys[id], _msize, OS_ENCRYPT);

    /* Clearing the message not encrypted */
    memset(_finmsg,'\0',_msize);
    memset(_msizechar,'\0', 6);

    if(msg_encrypted == NULL)
    {
        merror("(CreateSecMSG): Blowfish error");
        return(NULL);
    }

    snprintf(_msizechar,6,"%d",_msize);

    _mtotalsize = _msize+1 + strlen(keys->ids[id])+1+strlen(_msizechar)+2;

    _crypt_msg = (char *) calloc(_mtotalsize, sizeof(char *));
    
    if(_crypt_msg == NULL)
    {
        merror("(CreateSecMSG): Memory error");
        free(msg_encrypted);
        return(NULL);
    }

    /* Generating the message to be sent */
    snprintf(_crypt_msg,_mtotalsize-_msize,":%s:%s:",
            keys->ids[id],_msizechar);
    _mtotalsize--;

    for(i=_mtotalsize-_msize;i<_mtotalsize;i++)
        _crypt_msg[i]=msg_encrypted[j++];

    _crypt_msg[_mtotalsize]='\0';

    *msgsize = _mtotalsize+1;
    
    free(msg_encrypted);
    return(_crypt_msg);
}
			
/* EOF */
