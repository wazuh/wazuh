/* @(#) $Id: ./src/os_crypto/shared/msgs.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */



#include "shared.h"
#include "headers/sec.h"

#include "os_zlib/os_zlib.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"


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

int _s_verify_counter = 1;


/** OS_StartCounter.
 * Read counters for each agent.
 */
void OS_StartCounter(keystore *keys)
{
    int i;
    char rids_file[OS_FLSIZE +1];

    rids_file[OS_FLSIZE] = '\0';


    debug1("%s: OS_StartCounter: keysize: %d", __local_name, keys->keysize);


    /* Starting receiving counter */
    for(i = 0; i<=keys->keysize; i++)
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
                                           keys->keyentries[i]->id);
        }

        keys->keyentries[i]->fp = fopen(rids_file, "r+");

        /* If nothing is there, try to open as write only */
        if(!keys->keyentries[i]->fp)
        {
            keys->keyentries[i]->fp = fopen(rids_file, "w");
            if(!keys->keyentries[i]->fp)
            {
                int my_error = errno;

                /* Just in case we run out of file descriptiors */
                if((i > 10) && (keys->keyentries[i -1]->fp))
                {
                    fclose(keys->keyentries[i -1]->fp);

                    if(keys->keyentries[i -2]->fp)
                    {
                        fclose(keys->keyentries[i -2]->fp);
                    }
                }

                merror("%s: Unable to open agent file. errno: %d",
                       __local_name, my_error);
                ErrorExit(FOPEN_ERROR, __local_name, rids_file);
            }
        }
        else
        {
            unsigned int g_c = 0, l_c = 0;
            if(fscanf(keys->keyentries[i]->fp,"%u:%u", &g_c, &l_c) != 2)
            {
                if(i == keys->keysize)
                {
                    verbose("%s: INFO: No previous sender counter.", __local_name);
                }
                else
                {
                    verbose("%s: INFO: No previous counter available for '%s'.",
                                            __local_name,
                                            keys->keyentries[i]->name);
                }

                g_c = 0;
                l_c = 0;
            }

            if(i == keys->keysize)
            {
                verbose("%s: INFO: Assigning sender counter: %d:%d",
                            __local_name, g_c, l_c);
                global_count = g_c;
                local_count = l_c;
            }
            else
            {
                verbose("%s: INFO: Assigning counter for agent %s: '%d:%d'.",
                            __local_name, keys->keyentries[i]->name, g_c, l_c);

                keys->keyentries[i]->global = g_c;
                keys->keyentries[i]->local = l_c;
            }
        }
    }

    debug2("%s: DEBUG: Stored counter.", __local_name);

    /* Getting counter values */
    if(_s_recv_flush == 0)
    {
        _s_recv_flush = getDefine_Int("remoted",
                                      "recv_counter_flush",
                                      10, 999999);
    }

    /* Average printout values */
    if(_s_comp_print == 0)
    {
        _s_comp_print = getDefine_Int("remoted",
                                      "comp_average_printout",
                                      10, 999999);
    }


    _s_verify_counter = getDefine_Int("remoted", "verify_msg_id" , 0, 1);
}



/** OS_RemoveCounter(char *id)
 * Remove the ID counter.
 */
void OS_RemoveCounter(const char *id)
{
    char rids_file[OS_FLSIZE +1];
    snprintf(rids_file, OS_FLSIZE, "%s/%s",RIDS_DIR, id);
    unlink(rids_file);
}


/** StoreSenderCounter((keystore *keys, int global, int local)
 * Store sender counter.
 */
void StoreSenderCounter(const keystore *keys, int global, int local)
{
    /* Writting at the beginning of the file */
    fseek(keys->keyentries[keys->keysize]->fp, 0, SEEK_SET);
    fprintf(keys->keyentries[keys->keysize]->fp, "%u:%u:", global, local);
}


/* StoreCount(keystore *keys, int id, int global, int local)
 * Store the global and local count of events.
 */
void StoreCounter(const keystore *keys, int id, int global, int local)
{
    /* Writting at the beginning of the file */
    fseek(keys->keyentries[id]->fp, 0, SEEK_SET);
    fprintf(keys->keyentries[id]->fp, "%u:%u:", global, local);
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
    {
        return(NULL);
    }

    return(msg);
}



/* ReadSecMSG v0.2: 2005/02/10 */
char *ReadSecMSG(keystore *keys, char *buffer, char *cleartext,
                                 int id, int buffer_size)
{
    int cmp_size;
    unsigned int msg_global = 0;
    unsigned int msg_local = 0;

    char *f_msg;


    if(*buffer == ':')
    {
         buffer++;
    }
    else
    {
        merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
        return(NULL);
    }

    /* Decrypting message */
    if(!OS_BF_Str(buffer, cleartext, keys->keyentries[id]->key,
                  buffer_size, OS_DECRYPT))
    {
        merror(ENCKEY_ERROR, __local_name, keys->keyentries[id]->ip->ip);
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
        cmp_size = os_zlib_uncompress(cleartext, buffer, buffer_size, OS_MAXSTR);
        if(!cmp_size)
        {
            merror(UNCOMPRESS_ERR, __local_name);
            return(NULL);
        }

        /* Checking checksum  */
        f_msg = CheckSum(buffer);
        if(f_msg == NULL)
        {
            merror(ENCSUM_ERROR, __local_name, keys->keyentries[id]->ip->ip);
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
            merror(ENCFORMAT_ERROR, __local_name,keys->keyentries[id]->ip->ip);
            return(NULL);
        }
        f_msg++;

        msg_local = atoi(f_msg);
        f_msg+=5;


        /* Returning the message if we don't need to verify the counbter. */
        if(!_s_verify_counter)
        {
            /* Updating currently counts */
            keys->keyentries[id]->global = msg_global;
            keys->keyentries[id]->local = msg_local;
            if(rcv_count >= _s_recv_flush)
            {
                StoreCounter(keys, id, msg_global, msg_local);
                rcv_count = 0;
            }
            rcv_count++;
            return(f_msg);
        }


        if((msg_global > keys->keyentries[id]->global)||
           ((msg_global == keys->keyentries[id]->global) &&
            (msg_local > keys->keyentries[id]->local)))
        {
            /* Updating currently counts */
            keys->keyentries[id]->global = msg_global;
            keys->keyentries[id]->local = msg_local;

            if(rcv_count >= _s_recv_flush)
            {
                StoreCounter(keys, id, msg_global, msg_local);
                rcv_count = 0;
            }
            rcv_count++;
            return(f_msg);
        }


        /* Checking if it is a duplicated message */
        if(msg_global == keys->keyentries[id]->global)
        {
            return(NULL);
        }


        /* Warn about duplicated messages */
        merror("%s: WARN: Duplicate error:  global: %d, local: %d, "
                "saved global: %d, saved local:%d",
                __local_name,
                msg_global,
                msg_local,
                keys->keyentries[id]->global,
                keys->keyentries[id]->local);

        merror(ENCTIME_ERROR, __local_name, keys->keyentries[id]->name);
        return(NULL);
    }

    /* Old format */
    else if(cleartext[0] == ':')
    {
        unsigned int msg_count;
        time_t msg_time;

        /* Closing string */
        cleartext[buffer_size] = '\0';


        /* Checking checksum  */
        cleartext++;
        f_msg = CheckSum(cleartext);
        if(f_msg == NULL)
        {
            merror(ENCSUM_ERROR, __local_name, keys->keyentries[id]->ip->ip);
            return(NULL);
        }


        /* Checking time -- protecting against replay attacks */
        msg_time = atoi(f_msg);
        f_msg+=11;

        msg_count = atoi(f_msg);
        f_msg+=5;


        /* Returning the message if we don't need to verify the counbter. */
        if(!_s_verify_counter)
        {
            /* Updating currently counts */
            keys->keyentries[id]->global = msg_time;
            keys->keyentries[id]->local = msg_local;

            f_msg = strchr(f_msg, ':');
            if(f_msg)
            {
                f_msg++;
                return(f_msg);
            }
            else
            {
                merror(ENCFORMAT_ERROR, __local_name,keys->keyentries[id]->ip->ip);
                return (NULL);
            }
        }


        if((msg_time > keys->keyentries[id]->global) ||
           ((msg_time == keys->keyentries[id]->global)&&
            (msg_count > keys->keyentries[id]->local)))
        {
            /* Updating currently time and count */
            keys->keyentries[id]->global = msg_time;
            keys->keyentries[id]->local = msg_count;

            f_msg = strchr(f_msg, ':');
            if(f_msg)
            {
                f_msg++;
                return(f_msg);
            }
            else
            {
                merror(ENCFORMAT_ERROR, __local_name,keys->keyentries[id]->ip->ip);
                return (NULL);
            }
        }

        /* Checking if it is a duplicated message */
        if((msg_count == keys->keyentries[id]->local) &&
           (msg_time == keys->keyentries[id]->global))
        {
            return(NULL);
        }


        /* Warn about duplicated message */
        merror("%s: WARN: Duplicate error:  msg_count: %d, time: %d, "
                "saved count: %d, saved_time:%d",
                __local_name,
                msg_count,
                (int)msg_time,
                keys->keyentries[id]->local,
                keys->keyentries[id]->global);

        merror(ENCTIME_ERROR, __local_name, keys->keyentries[id]->name);
        return(NULL);
    }

    merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
    return(NULL);
}



/* Creat a encrypted message.
 * Returns the size of it
 */
int CreateSecMSG(const keystore *keys, const char *msg, char *msg_encrypted, int id)
{
    int bfsize;
    int msg_size;
    int cmp_size;

    u_int16_t rand1;

    char _tmpmsg[OS_MAXSTR + 2];
    char _finmsg[OS_MAXSTR + 2];

    os_md5 md5sum;

    msg_size = strlen(msg);


    /* Checking for invalid msg sizes */
    if((msg_size > (OS_MAXSTR - OS_HEADER_SIZE))||(msg_size < 1))
    {
        merror(ENCSIZE_ERROR, __local_name, msg);
        return(0);
    }

    /* Random number */
    rand1 = (u_int16_t)random();


    _tmpmsg[OS_MAXSTR +1] = '\0';
    _finmsg[OS_MAXSTR +1] = '\0';
    msg_encrypted[OS_MAXSTR] = '\0';


    /* Increasing local and global counters */
    if(local_count >= 9997)
    {
        local_count = 0;
        global_count++;
    }
    local_count++;


    snprintf(_tmpmsg, OS_MAXSTR,"%05hu%010u:%04u:%s",
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
    cmp_size = os_zlib_compress(_finmsg, _tmpmsg + 8, msg_size, OS_MAXSTR - 12);
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
        verbose("%s: INFO: Event count after '%u': %u->%u (%d%%)", __local_name,
                    evt_count,
                    c_orig_size,
                    c_comp_size,
                    (c_comp_size * 100)/c_orig_size);
        evt_count = 0;
        c_orig_size = 0;
        c_comp_size = 0;
    }
    evt_count++;

    /* If the ip is dynamic (not single host, append agent id
     * to the message.
     */
    if(!isSingleHost(keys->keyentries[id]->ip) && isAgent)
    {
        snprintf(msg_encrypted, 16, "!%s!:", keys->keyentries[id]->id);
        msg_size = strlen(msg_encrypted);
    }
    else
    {
        /* Setting beginning of the message */
        msg_encrypted[0] = ':';
        msg_size = 1;
    }


    /* msg_size is the ammount of non-encrypted message
     * appended to the buffer. On dynamic ips, it will
     * include the agent id.
     */

    /* Encrypting everything */
    OS_BF_Str(_tmpmsg + (7 - bfsize), msg_encrypted + msg_size,
                                      keys->keyentries[id]->key,
                                      cmp_size,
                                      OS_ENCRYPT);


    /* Storing before leaving */
    StoreSenderCounter(keys, global_count, local_count);

    return(cmp_size + msg_size);
}


/* EOF */
