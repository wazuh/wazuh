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


#include "shared.h"
#include "headers/sec.h"

#include "os_zlib/os_zlib.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"

/** Remote IDS directory */
#ifndef WIN32
#define RIDS_DIR        "/queue/rids"
#else
#define RIDS_DIR        "rids"
#endif
#define SENDER_COUNTER  "sender_counter"
#define KEYSIZE	        128 


/** Sending counts **/
unsigned int global_count = 0;
unsigned int local_count  = 0;

/** Average compression rates **/
int evt_count = 0;
int rcv_count = 0;
unsigned int c_orig_size = 0;
unsigned int c_comp_size = 0;


/** Static variables (read from define file) **/
int _s_comp_print = 0;
int _s_recv_flush = 0;


/** Function Prototypes **/
void StartCounter(keystruct *keys);


/* _MemClear v0.1 - Internal use */
void _MemClear(char *id, char *name, char *ip, char *key)
{
	memset(id,'\0', KEYSIZE +1);
	memset(name,'\0',KEYSIZE +1);
	memset(key,'\0', KEYSIZE +1);
	memset(ip,'\0', KEYSIZE +1);
}


/* _CHash v0.1 -Internal use  */
void _CHash(keystruct *keys, char *id, char *name, char *ip, char *key)
{
	os_md5 filesum1;
	os_md5 filesum2;
    
	char _finalstr[KEYSIZE];
    
    struct sockaddr_in peer;
    
    /* Allocating for the whole structure */
	keys->ids = (char **)realloc(keys->ids,
			(keys->keysize+1) * sizeof(char *));

    keys->ips = (char **)realloc(keys->ips,
            (keys->keysize+1)* sizeof(char*));

    keys->name = (char **)realloc(keys->name,
            (keys->keysize+1)* sizeof(char*));
    
    keys->peer_info = realloc(keys->peer_info,
            (keys->keysize+1) * sizeof(peer));
   
    keys->global = realloc(keys->global, (keys->keysize+1) * sizeof(int)); 
    keys->local = realloc(keys->local, (keys->keysize+1) * sizeof(int)); 
    keys->rcvd = realloc(keys->rcvd, (keys->keysize+1) * sizeof(int)); 
    keys->fps = realloc(keys->fps, (keys->keysize+2) * sizeof(FILE *));
    
    if(!keys->ids || !keys->ips || !keys->peer_info
                  || !keys->global|| !keys->local
                  || !keys->rcvd || !keys->name || !keys->fps) 
    {
        ErrorExit(MEM_ERROR, __local_name);
    }
    
    /* Setting configured values */
	keys->ids[keys->keysize] = strdup(id);
	keys->ips[keys->keysize] = strdup(ip);
	keys->name[keys->keysize] = strdup(name);


    /* Initializing the variables */
    keys->local[keys->keysize] = 0;
    keys->global[keys->keysize] = 0;
    keys->rcvd[keys->keysize] = 0;


    if(!keys->ids[keys->keysize] || 
       !keys->ips[keys->keysize] ||
       !keys->name[keys->keysize])
    {
        ErrorExit(MEM_ERROR, __local_name);
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
	memset(_finalstr,'\0', sizeof(_finalstr));
	snprintf(_finalstr, 49, "%s%s", filesum2, filesum1);


    /* Final key is 48 * 4 = 192bits */
    keys->keys = (char **)realloc(keys->keys,
			(keys->keysize+1)*sizeof(char *));
	if(keys->keys == NULL)
       ErrorExit(MEM_ERROR, __local_name); 


    keys->keys[keys->keysize]=strdup(_finalstr);
    
    if(keys->keys[keys->keysize] == NULL)
       ErrorExit(MEM_ERROR, __local_name); 



	/* Cleaning final string from memory */
	memset(_finalstr,'\0', sizeof(_finalstr));


	/* next */
	keys->keysize++;	
    
	return;
}



/* ReadKeys v0.1: 2005/02/01 */
void ReadKeys(keystruct *keys, int just_read)
{
    FILE *fp;
    
    char buffer[OS_BUFFER_SIZE +1];
    
    char name[KEYSIZE +1];
    char ip[KEYSIZE +1];
    char id[KEYSIZE +1];
    char key[KEYSIZE +1];
    

    if(File_DateofChange(KEYS_FILE) < 0)
    {
        merror(NO_AUTHFILE, __local_name, KEYS_FILE);
        ErrorExit(NO_REM_CONN, __local_name);
    }

    fp = fopen(KEYS_FILE,"r");
    if(!fp)
    {
        /* We can leave from here */
        merror(FOPEN_ERROR, __local_name, KEYS_FILE);
        ErrorExit(NO_REM_CONN, __local_name);
    }


    /* Initializing structure */
    keys->ids = NULL;
    keys->keys = NULL;
    keys->ips = NULL;
    keys->global = NULL;
    keys->local = NULL;
    keys->name = NULL;
    keys->rcvd = NULL;
    keys->peer_info = NULL;
    keys->fps = NULL;
    keys->keysize = 0;

    _MemClear(id, name, ip, key);

    memset(buffer, '\0', OS_BUFFER_SIZE +1);

    /* Reading each line.
     * lines are divided on id name ip key
     */
    while(fgets(buffer, OS_BUFFER_SIZE, fp) != NULL)
    {
        char *tmp_str;
        char *valid_str;
        
        if((buffer[0] == '#') || (buffer[0] == ' '))
            continue;


        /* Getting ID */
        valid_str = buffer;
        tmp_str = strchr(buffer, ' ');
        if(!tmp_str)
        {
            merror(INVALID_KEY, __local_name, buffer);
            continue;
        }

        *tmp_str = '\0';
        tmp_str++;

        strncpy(id, valid_str, KEYSIZE -1);


        /* Getting name */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        if(!tmp_str)
        {
            merror(INVALID_KEY, __local_name, buffer);
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(name, valid_str, KEYSIZE -1);

         
        /* Getting ip address */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, ' ');
        if(!tmp_str)
        {
            merror(INVALID_KEY, __local_name, buffer);
        }

        *tmp_str = '\0';
        tmp_str++;
        strncpy(ip, valid_str, KEYSIZE -1);

        
        /* Getting key */
        valid_str = tmp_str;
        tmp_str = strchr(tmp_str, '\n');
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


    /* Checking if there is any agent available */
    if(keys->keysize == 0)
    {
        ErrorExit(NO_REM_CONN, __local_name);
    }


    /* Opening count files */
    if(!just_read)
    {
        /* Reading the counters */
        StartCounter(keys);
    }
    
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



/* IsAllowedID v0.1: 2005/11/19 */
int IsAllowedID(keystruct *keys, char *id)
{
    int i = 0;

    if(id == NULL)
        return(-1);
   
    for(i = 0; i < keys->keysize; i++)
    {
        if(strcmp(keys->ids[i],id) == 0)
            return(i);
    }
    return(-1);
}


/* StartCounter and read saved values */
void StartCounter(keystruct *keys)
{
    int i;
    char rids_file[OS_FLSIZE +1];

    rids_file[OS_FLSIZE] = '\0';
    
    /* Starting receiving counter */
    for(i = 0;i<=keys->keysize;i++)
    {
        /* On i == keysize, we deal with the
         * sender counter.
         */
        if(i == keys->keysize)
        {
            snprintf(rids_file, OS_FLSIZE, "%s/%s",
                                            RIDS_DIR,
                                            SENDER_COUNTER);
        }
        else
        {
            snprintf(rids_file, OS_FLSIZE, "%s/%s",
                                           RIDS_DIR,
                                           keys->ids[i]);
        }
        keys->fps[i] = fopen(rids_file, "r+");
        
        /* If there nothing there, try to open as write only */
        if(!keys->fps[i])
        {
            keys->fps[i] = fopen(rids_file, "w");
            if(!keys->fps[i])
            {
                ErrorExit(FOPEN_ERROR, __local_name, rids_file);
            }
        }
        else
        {
            unsigned int g_c = 0, l_c = 0;
            if(fscanf(keys->fps[i],"%u:%u", &g_c, &l_c) != 2)
            {
                if(i == keys->keysize)
                {
                    verbose("%s: No previous sender counter.", __local_name);
                }
                else
                {
                    verbose("%s: No previous counter available for '%s'.",
                                            __local_name, keys->name[i]);
                }
                
                g_c = 0;
                l_c = 0;
            }

            if(i == keys->keysize)
            {
                verbose("%s: Assigning sender counter: %d:%d",
                            __local_name, g_c, l_c);
                global_count = g_c;
                local_count = l_c;
            }
            else
            {
                verbose("%s: Assigning counter for agent %s: '%d:%d'.",
                            __local_name, keys->name[i], g_c, l_c);
                            
                keys->global[i] = g_c;
                keys->local[i] = l_c;
            }
        }
    }


    /* Getting counter values */
    _s_recv_flush = getDefine_Int("remoted",
                                  "recv_counter_flush",
                                  10, 999999);

    /* Average printout values */
    _s_comp_print = getDefine_Int("remoted",
                                  "comp_average_printout",
                                  10, 999999);
}


/** RemoveCounter(char *id)
 * Remove the ID counter.
 */
void RemoveCounter(char *id)
{
    char rids_file[OS_FLSIZE +1];
    snprintf(rids_file, OS_FLSIZE, "%s/%s",RIDS_DIR, id);
    unlink(rids_file);
}


/** StoreSenderCounter((keystruct *keys, int global, int local)
 * Store sender counter.
 */
void StoreSenderCounter(keystruct *keys, int global, int local)
{
    /* Writting at the beginning of the file */
    fseek(keys->fps[keys->keysize], 0, SEEK_SET);
    fprintf(keys->fps[keys->keysize], "%u:%u:", global, local);
}


/* StoreCount(keystruct *keys, int id, int global, int local)
 * Store the global and local count of events.
 */
void StoreCounter(keystruct *keys, int id, int global, int local)
{
    /* Writting at the beginning of the file */
    fseek(keys->fps[id], 0, SEEK_SET);
    fprintf(keys->fps[id], "%u:%u:", global, local);
}


/* CheckSum v0.1: 2005/02/15 
 * Verify the checksum of the message.
 * Returns NULL on error or the message on success.
 */
char *CheckSum(char *msg)
{
    os_md5 recvd_sum;
    os_md5 checksum;


    /* Better way */
    strncpy(recvd_sum,msg,32);
    recvd_sum[32]='\0';

    msg+=32;

    OS_MD5_Str(msg, checksum);
    if(strncmp(checksum,recvd_sum,32) != 0)
        return(NULL);
    
    return(msg);
}



/* ReadSecMSG v0.2: 2005/02/10 */
char *ReadSecMSG(keystruct *keys, char *buffer, char *cleartext, 
                                  int id, int buffer_size)
{
    int cmp_size;
    unsigned int msg_global;
    unsigned int msg_local;

    char *f_msg;
    
    if(*buffer != ':')
    {
        merror(ENCFORMAT_ERROR, __local_name, keys->ips[id]);
        return(NULL);
    }

    buffer++; /* to next : */


    /* Decrypting message */
    if(!OS_BF_Str(buffer, cleartext, keys->keys[id], buffer_size, OS_DECRYPT)) 
    {
        merror(ENCKEY_ERROR, __local_name, keys->ips[id]);
        return(NULL);
    }


    /* Compressed */
    else if(cleartext[0] == '!')
    {
        cleartext[buffer_size] = '\0';
        cleartext++;
        buffer_size--;

        /* Removing padding */
        while(*cleartext == '!')
        {
            cleartext++;
            buffer_size--;
        }
        
        /* Uncompressing */
        cmp_size = os_uncompress(cleartext, buffer, buffer_size, OS_MAXSTR);
        if(!cmp_size)
        {
            merror(UNCOMPRESS_ERR, __local_name);
            return(NULL);
        }

        /* Checking checksum  */
        f_msg = CheckSum(buffer);
        if(f_msg == NULL)
        {
            merror(ENCSUM_ERROR, __local_name, keys->ips[id]);
            return(NULL);
        }

        /* Removing random */
        f_msg+=5;


        /* Checking count -- protecting against replay attacks */
        msg_global = atoi(f_msg);
        f_msg+=10;

        /* Checking for the right message format */
        if(*f_msg != ':')
        {
            merror(ENCFORMAT_ERROR, __local_name, keys->ips[id]);
            return(NULL);
        }
        f_msg++;

        msg_local = atoi(f_msg);
        f_msg+=5;

        if((msg_global > keys->global[id])||
           ((msg_global == keys->global[id]) && (msg_local > keys->local[id])))
        {
            /* Updating currently counts */
            keys->global[id] = msg_global;
            keys->local[id] = msg_local;

            if(rcv_count >= _s_recv_flush)
            {
                StoreCounter(keys, id, msg_global, msg_local);
                rcv_count = 0;
            }
            rcv_count++;
            return(f_msg);
        }

        /* Checking if it is a duplicated message */
        if(msg_global == keys->global[id])
        {
            return(NULL);
        }


        /* Warn about duplicated messages */
        merror("%s: Duplicate error:  global: %d, local: %d, "
                "saved global: %d, saved local:%d",
                __local_name,
                msg_global,
                msg_local,
                keys->global[id],
                keys->local[id]);

        merror(ENCTIME_ERROR, __local_name, keys->ips[id]);
        return(NULL);
    }

    /* Old format */
    else if(cleartext[0] == ':')
    {
        int msg_count;
        time_t msg_time;

        /* Closing string */
        cleartext[buffer_size] = '\0';


        /* Checking checksum  */
        cleartext++;
        f_msg = CheckSum(cleartext);
        if(f_msg == NULL)
        {
            merror(ENCSUM_ERROR, __local_name, keys->ips[id]);
            return(NULL);
        }


        /* Checking time -- protecting against replay attacks */
        msg_time = atoi(f_msg);
        f_msg+=11;

        msg_count = atoi(f_msg);
        f_msg+=5;

        if((msg_time > keys->global[id]) ||
           ((msg_time == keys->global[id])&&(msg_count > keys->local[id])))
        {
            /* Updating currently time and count */
            keys->global[id] = msg_time;
            keys->local[id] = msg_count;

            f_msg = strchr(f_msg, ':');
            if(f_msg)
            {
                f_msg++;
                return(f_msg);
            }
        }

        /* Checking if it is a duplicated message */
        if((msg_count == keys->local[id]) && (msg_time == keys->global[id]))
        {
            return(NULL);
        }


        /* Warn about duplicated message */
        merror("%s: Duplicate error:  msg_count: %d, time: %d, "
                "saved count: %d, saved_time:%d",
                __local_name,
                msg_count,
                msg_time,
                keys->local[id],
                keys->global[id]);

        merror(ENCTIME_ERROR, __local_name, keys->ips[id]);
        return(NULL);
    }
    
    merror(ENCFORMAT_ERROR, __local_name, keys->ips[id]);
    return(NULL);
}



/* Creat a encrypted message.
 * Returns the size of it
 */
int CreateSecMSG(keystruct *keys, char *msg, char *msg_encrypted,
                                  int id)
{
    int bfsize;
    int msg_size;
    int cmp_size;
    
    u_int16_t rand1;
    
    char _tmpmsg[OS_MAXSTR +2];
    char _finmsg[OS_MAXSTR +2];
    
    os_md5 md5sum;
    
    msg_size = strlen(msg);
    
    if((msg_size > (OS_MAXSTR - OS_HEADER_SIZE))||(msg_size < 1))
    {
        merror(ENCSIZE_ERROR, __local_name, msg);
        return(0);
    }
    
    /* Random number */
    rand1 = (u_int16_t)rand();

    _tmpmsg[OS_MAXSTR +1] = '\0';
    _finmsg[OS_MAXSTR +1] = '\0';
    msg_encrypted[OS_MAXSTR] = '\0';
   
    if(local_count >= 9997)
    {
        local_count = 0;
        global_count++;
    }
    local_count++;
    
    
    snprintf(_tmpmsg, OS_MAXSTR,"%05hu%010u:%04hu:%s",
                              rand1, global_count, local_count,
                              msg);  

    
    /* Generating md5sum of the unencrypted string */
    OS_MD5_Str(_tmpmsg, md5sum);


    
    /* Generating final msg to be compressed */
    snprintf(_finmsg, OS_MAXSTR,"%s%s",md5sum,_tmpmsg);
    msg_size = strlen(_finmsg);


    /* Compressing message.
     * We assing the first 8 bytes for padding. 
     */
    cmp_size = os_compress(_finmsg, _tmpmsg + 8, msg_size, OS_MAXSTR - 12);
    if(!cmp_size)
    {
        merror(COMPRESS_ERR, __local_name, _finmsg);
        return(0);
    }
    cmp_size++;
    
    /* Padding the message (needs to be div by 8) */
    bfsize = 8 - (cmp_size % 8);
    if(bfsize == 8)
        bfsize = 0;

    _tmpmsg[0] = '!';
    _tmpmsg[1] = '!';
    _tmpmsg[2] = '!';
    _tmpmsg[3] = '!';
    _tmpmsg[4] = '!';
    _tmpmsg[5] = '!';
    _tmpmsg[6] = '!';
    _tmpmsg[7] = '!';

    cmp_size+=bfsize;


    /* Getting average sizes */
    c_orig_size+= msg_size;
    c_comp_size+= cmp_size;
    if(evt_count > _s_comp_print)
    {
        verbose("%s: Event count after '%u': %u->%u (%d%%)", __local_name,
                    evt_count,
                    c_orig_size, 
                    c_comp_size,
                    (c_comp_size * 100)/c_orig_size);
        evt_count = 0;
        c_orig_size = 0;
        c_comp_size = 0;
    }
    evt_count++;
    
    /* Setting beginning of the message */
    msg_encrypted[0] = ':';
    msg_encrypted++;

    
    /* Encrypting everything */
    OS_BF_Str(_tmpmsg + (7 - bfsize), msg_encrypted, 
                                      keys->keys[id], 
                                      cmp_size, 
                                      OS_ENCRYPT);
    
    msg_encrypted--;

    /* Storing before leaving */
    StoreSenderCounter(keys, global_count, local_count);

    return(cmp_size +1);
}


/* EOF */
