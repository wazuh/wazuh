/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "headers/sec.h"
#include "os_zlib/os_zlib.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"
#include "os_crypto/aes/aes_op.h"
#include "client-agent/agentd.h"

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

/* Prototypes */
static void StoreSenderCounter(const keystore *keys, unsigned int global, unsigned int local) __attribute((nonnull));
static void StoreCounter(const keystore *keys, int id, unsigned int global, unsigned int local) __attribute((nonnull));
static void ReloadCounter(const keystore *keys, unsigned int id, const char * cid) __attribute((nonnull));
static char *CheckSum(char *msg, size_t length) __attribute((nonnull));

/* Sending counts */
static unsigned int global_count = 0;
static unsigned int local_count  = 0;

/* Average compression rates */
static unsigned int evt_count = 0;
static unsigned int rcv_count = 0;
static size_t c_orig_size = 0;
static size_t c_comp_size = 0;

/* Global variables (read from define file) */
unsigned int _s_comp_print = 0;
unsigned int _s_recv_flush = 0;
int _s_verify_counter = 1;



/* Crypto methods function */
int doEncryptByMethod(const char *input, char *output, const char *charkey,
    long size, short int action,int method)
{
    switch(method)
    {
        case W_METH_BLOWFISH:
            return OS_BF_Str(input, output,
                    charkey,
                    size,
                    action);
        case W_METH_AES:
            return OS_AES_Str(input, output,
                charkey,
                size,
                action);

        default:
            return OS_INVALID;
    }
}

/* Set the agent crypto method read from the ossec.conf file */
void os_set_agent_crypto_method(keystore * keys,const int method){
    keys->keyentries[0]->crypto_method = method;
}

static time_t saved_time = 0;

/* Read counters for each agent */
void OS_StartCounter(keystore *keys)
{
    unsigned int i;
    char rids_file[OS_FLSIZE + 1];

    rids_file[OS_FLSIZE] = '\0';

    mdebug1("OS_StartCounter: keysize: %u", keys->keysize);

    /* Start receiving counter */
    for (i = 0; i <= keys->keysize; i++) {
        /* On i == keysize, we deal with the sender counter */
        if (i == keys->keysize) {
            snprintf(rids_file, OS_FLSIZE, "%s/%s",
                     isChroot() ? RIDS_DIR : RIDS_DIR_PATH,
                     SENDER_COUNTER);
        } else {
            snprintf(rids_file, OS_FLSIZE, "%s/%s",
                     isChroot() ? RIDS_DIR : RIDS_DIR_PATH,
                     keys->keyentries[i]->id);
        }

        keys->keyentries[i]->fp = fopen(rids_file, "r+");

        /* If nothing is there, try to open as write only */
        if (!keys->keyentries[i]->fp) {
            keys->keyentries[i]->fp = fopen(rids_file, "w");
            if (!keys->keyentries[i]->fp) {
                int my_error = errno;

                merror("Unable to open agent file. errno: %d", my_error);
                merror_exit(FOPEN_ERROR, rids_file, errno, strerror(errno));
            }
        } else {
            unsigned int g_c = 0, l_c = 0;
            if (fscanf(keys->keyentries[i]->fp, "%u:%u", &g_c, &l_c) != 2) {
                if (i == keys->keysize) {
                    mdebug1("No previous sender counter.");
                } else {
                    mdebug1("No previous counter available for '%s'.",
                            keys->keyentries[i]->name);
                }

                g_c = 0;
                l_c = 0;
            }

            if (i == keys->keysize) {
                mdebug1("Assigning sender counter: %u:%u",
                        g_c, l_c);
                global_count = g_c;
                local_count = l_c;
            } else {
                mdebug1("Assigning counter for agent %s: '%u:%u'.",
                        keys->keyentries[i]->name, g_c, l_c);

                keys->keyentries[i]->global = g_c;
                keys->keyentries[i]->local = l_c;
            }
        }
        if (i != keys->keysize) {
            fclose(keys->keyentries[i]->fp);
            keys->keyentries[i]->fp = NULL;
        }

        keys->keyentries[i]->inode = File_Inode(rids_file);
    }

    mdebug2("Stored counter.");
    keys->opened_fp_queue = linked_queue_init();

    /* Get counter values */
    if (_s_recv_flush == 0) {
        _s_recv_flush = (unsigned int) getDefine_Int("remoted",
                        "recv_counter_flush",
                        10, 999999);
    }

    /* Average printout values */
    if (_s_comp_print == 0) {
        _s_comp_print = (unsigned int) getDefine_Int("remoted",
                        "comp_average_printout",
                        10, 999999);
    }


    _s_verify_counter = getDefine_Int("remoted", "verify_msg_id" , 0, 1);
}

/* Remove the ID counter */
void OS_RemoveCounter(const char *id)
{
    char rids_file[OS_FLSIZE + 1];
    snprintf(rids_file, OS_FLSIZE, "%s/%s", RIDS_DIR, id);
    unlink(rids_file);
}

/* Store sender counter */
static void StoreSenderCounter(const keystore *keys, unsigned int global, unsigned int local)
{
    /* Write to the beginning of the file */
    fseek(keys->keyentries[keys->keysize]->fp, 0, SEEK_SET);
    fprintf(keys->keyentries[keys->keysize]->fp, "%u:%u:", global, local);
    fflush(keys->keyentries[keys->keysize]->fp);
}

/* Store the global and local count of events */
static void StoreCounter(const keystore *keys, int id, unsigned int global, unsigned int local)
{
    if (!keys->keyentries[id]->fp) {
        char rids_file[OS_FLSIZE + 1];
        snprintf(rids_file, OS_FLSIZE, "%s/%s", isChroot() ? RIDS_DIR : RIDS_DIR_PATH, keys->keyentries[id]->id);
        keys->keyentries[id]->fp = fopen(rids_file, "r+");
        if (!keys->keyentries[id]->fp) {
            keys->keyentries[id]->fp = fopen(rids_file, "w");
            if (!keys->keyentries[id]->fp) {
                int my_error = errno;

                merror("Unable to open agent file. errno: %d", my_error);
                merror_exit(FOPEN_ERROR, rids_file, errno, strerror(errno));
            }
        }
        mdebug2("Opening rids for agent %s.", keys->keyentries[id]->id);
    }

    /* Write to the beginning of the file */
    fseek(keys->keyentries[id]->fp, 0, SEEK_SET);
    fprintf(keys->keyentries[id]->fp, "%u:%u:", global, local);
    fflush(keys->keyentries[id]->fp);

    keys->keyentries[id]->updating_time = time(0);
    if (!keys->keyentries[id]->rids_node) {
        mdebug2("Pushing rids_node for agent %s.", keys->keyentries[id]->id);
        keys->keyentries[id]->rids_node = linked_queue_push_ex(keys->opened_fp_queue, keys->keyentries[id]);
    } else {
        mdebug2("Updating rids_node for agent %s.", keys->keyentries[id]->id);
        linked_queue_unlink_and_push_node(keys->opened_fp_queue, keys->keyentries[id]->rids_node);
    }
}

/* Reload the global and local count of events */
static void ReloadCounter(const keystore *keys, unsigned int id, const char * cid)
{
    ino_t new_inode;
    char rids_file[OS_FLSIZE + 1];

    snprintf(rids_file, OS_FLSIZE, "%s/%s", isChroot() ? RIDS_DIR : RIDS_DIR_PATH, cid);
    new_inode = File_Inode(rids_file);

    if (keys->keyentries[id]->inode != new_inode) {
        keys->keyentries[id]->fp = fopen(rids_file, "r+");

        if (!keys->keyentries[id]->fp) {
            keys->keyentries[id]->fp = fopen(rids_file, "w");
            if (!keys->keyentries[id]->fp) {
                goto fail_open;
            }
        }
        else {
            unsigned int g_c = 0;
            unsigned int l_c = 0;

            if (fscanf(keys->keyentries[id]->fp, "%u:%u", &g_c, &l_c) != 2) {
                if (id == keys->keysize) {
                    mdebug1("No previous sender counter.");
                } else {
                    mdebug1("No previous counter available for '%s'.", keys->keyentries[id]->id);
                }

                g_c = 0;
                l_c = 0;
            }

            if (id == keys->keysize) {
                mdebug1("Reloading sender counter: %u:%u", g_c, l_c);
                global_count = g_c;
                local_count = l_c;
            } else {
                mdebug1("Reloading counter for agent %s: '%u:%u'.", keys->keyentries[id]->id, g_c, l_c);

                keys->keyentries[id]->global = g_c;
                keys->keyentries[id]->local = l_c;
            }
        }

        keys->keyentries[id]->inode = new_inode;
    }

    return;

fail_open:
    merror("Unable to reload counter '%s': %s (%d)", cid, strerror(errno), errno);
}

/* Verify the checksum of the message
 * Returns NULL on error or the message on success
 */
static char *CheckSum(char *msg, size_t length)
{
    os_md5 recvd_sum;
    os_md5 checksum;

    /* Better way */
    strncpy(recvd_sum, msg, 32);
    recvd_sum[32] = '\0';

    msg += 32;

    OS_MD5_Str(msg, (ssize_t)length - 32, checksum);

    if (strncmp(checksum, recvd_sum, 32) != 0) {
        return (NULL);
    }

    return (msg);
}

int ReadSecMSG(keystore *keys, char *buffer, char *cleartext, int id, unsigned int buffer_size, size_t *final_size, const char *srcip, char **output)
{
    unsigned int msg_global = 0;
    unsigned int msg_local = 0;
    char *f_msg;

    if(strncmp(buffer, "#AES", 4)==0){
        buffer+=4;
        #ifndef CLIENT
            keys->keyentries[id]->crypto_method = W_METH_AES;
        #endif
    }
    else{
        #ifndef CLIENT
            keys->keyentries[id]->crypto_method = W_METH_BLOWFISH;
        #endif
    }


    if (*buffer == ':') {
        buffer++;
    } else {
        merror(ENCFORMAT_ERROR, keys->keyentries[id]->id, srcip);
        return KS_CORRUPT;
    }

    /* Decrypt message */
    switch(keys->keyentries[id]->crypto_method){
        case W_METH_BLOWFISH:
            if (!OS_BF_Str(buffer, cleartext, keys->keyentries[id]->key,
                        buffer_size, OS_DECRYPT)) {
                mwarn(ENCKEY_ERROR, keys->keyentries[id]->id, keys->keyentries[id]->ip->ip);
                return KS_ENCKEY;
            }
            break;
        case W_METH_AES:
            if (!OS_AES_Str(buffer, cleartext, keys->keyentries[id]->key,
                buffer_size-4, OS_DECRYPT)) {
                mwarn(ENCKEY_ERROR, keys->keyentries[id]->id, keys->keyentries[id]->ip->ip);
                return KS_ENCKEY;
            }
            break;
    }

    /* Compressed */
    if (cleartext[0] == '!') {
        cleartext[buffer_size] = '\0';
        cleartext++;
        buffer_size--;

        /* Remove padding */
        while (*cleartext == '!') {
            cleartext++;
            buffer_size--;
        }

        /* Uncompress */
        if (*final_size = os_zlib_uncompress(cleartext, buffer, buffer_size, OS_MAXSTR), !*final_size) {
#ifdef CLIENT
            merror(UNCOMPRESS_ERR);
#else
            merror(UNCOMPRESS_ERR " Message received from agent '%s' at '%s'", keys->keyentries[id]->id, keys->keyentries[id]->ip->ip);
#endif
            return KS_CORRUPT;
        }

        /* Check checksum */
        if (f_msg = CheckSum(buffer, *final_size), !f_msg) {
            merror(ENCSUM_ERROR, keys->keyentries[id]->id, keys->keyentries[id]->ip->ip);
            return KS_CORRUPT;
        }

        /* Remove random */
        f_msg += 5;

        /* Check count -- protect against replay attacks */
        msg_global = (unsigned int) atoi(f_msg);
        f_msg += 10;

        /* Check for the right message format */
        if (*f_msg != ':') {
            merror(ENCFORMAT_ERROR, keys->keyentries[id]->id, srcip);
            return KS_CORRUPT;
        }
        f_msg++;

        msg_local = (unsigned int) atoi(f_msg);
        f_msg += 5;
        *final_size -= (f_msg - buffer);

        w_mutex_lock(&keys->keyentries[id]->mutex);

        /* Return the message if we don't need to verify the counter */
        if (!_s_verify_counter) {
            /* Update current counts */
            keys->keyentries[id]->global = msg_global;
            keys->keyentries[id]->local = msg_local;
            if (rcv_count >= _s_recv_flush) {
                StoreCounter(keys, id, msg_global, msg_local);
                rcv_count = 0;
            }
            rcv_count++;
            w_mutex_unlock(&keys->keyentries[id]->mutex);
            *output = f_msg;
            return KS_VALID;
        }

        if (rcv_count >= _s_recv_flush) {
            ReloadCounter(keys, id, keys->keyentries[id]->id);
        }
        if ((msg_global > keys->keyentries[id]->global) ||
                ((msg_global == keys->keyentries[id]->global) &&
                 (msg_local > keys->keyentries[id]->local))) {
            /* Update current counts */
            keys->keyentries[id]->global = msg_global;
            keys->keyentries[id]->local = msg_local;

            if (rcv_count >= _s_recv_flush) {
                StoreCounter(keys, id, msg_global, msg_local);
                rcv_count = 0;
            }
            rcv_count++;
            w_mutex_unlock(&keys->keyentries[id]->mutex);
            *output = f_msg;
            return KS_VALID;
        }

        /* Check if it is a duplicated message */
        if (msg_global == keys->keyentries[id]->global) {
            /* Warn about duplicated messages */
            mwarn("Duplicate error:  global: %u, local: %u, "
                "saved global: %u, saved local:%u",
                msg_global,
                msg_local,
                keys->keyentries[id]->global,
                keys->keyentries[id]->local);
            w_mutex_unlock(&keys->keyentries[id]->mutex);
            merror(ENCTIME_ERROR, keys->keyentries[id]->name);
            return KS_RIDS;
        }
        w_mutex_unlock(&keys->keyentries[id]->mutex);
    }

    /* Old format */
    else if (cleartext[0] == ':') {
        unsigned int msg_count;
        unsigned int msg_time;

        /* Close string */
        cleartext[buffer_size] = '\0';

        /* Check checksum */
        cleartext++;
        f_msg = CheckSum(cleartext, buffer_size);
        if (f_msg == NULL) {
            merror(ENCSUM_ERROR, keys->keyentries[id]->id, keys->keyentries[id]->ip->ip);
            return KS_CORRUPT;
        }

        /* Check time -- protect against replay attacks */
        msg_time = (unsigned int) atoi(f_msg);
        f_msg += 11;

        msg_count = (unsigned int) atoi(f_msg);
        f_msg += 5;

        w_mutex_lock(&keys->keyentries[id]->mutex);

        /* Return the message if we don't need to verify the counter */
        if (!_s_verify_counter) {
            /* Update current counts */
            keys->keyentries[id]->global = msg_time;
            keys->keyentries[id]->local = msg_local;

            f_msg = strchr(f_msg, ':');
            if (f_msg) {
                f_msg++;
                *final_size = buffer_size - (f_msg - cleartext);
                *output = f_msg;
                w_mutex_unlock(&keys->keyentries[id]->mutex);
                return KS_VALID;
            } else {
                w_mutex_unlock(&keys->keyentries[id]->mutex);
                merror(ENCFORMAT_ERROR, keys->keyentries[id]->id, srcip);
                return KS_CORRUPT;
            }
        }

        if ((msg_time > keys->keyentries[id]->global) ||
                ((msg_time == keys->keyentries[id]->global) &&
                 (msg_count > keys->keyentries[id]->local))) {
            /* Update current time and count */
            keys->keyentries[id]->global = msg_time;
            keys->keyentries[id]->local = msg_count;

            f_msg = strchr(f_msg, ':');
            if (f_msg) {
                f_msg++;
                *final_size = buffer_size - (f_msg - cleartext);
                *output = f_msg;
                w_mutex_unlock(&keys->keyentries[id]->mutex);
                return KS_VALID;
            } else {
                w_mutex_unlock(&keys->keyentries[id]->mutex);
                merror(ENCFORMAT_ERROR, keys->keyentries[id]->id, srcip);
                return KS_CORRUPT;
            }
        }

        /* Check if it is a duplicated message */
        if ((msg_count == keys->keyentries[id]->local) &&
                (msg_time == keys->keyentries[id]->global)) {

            w_mutex_unlock(&keys->keyentries[id]->mutex);
            return KS_RIDS;
        }

        /* Warn about duplicated message */
        mwarn("Duplicate error:  msg_count: %u, time: %u, "
               "saved count: %u, saved_time:%u",
               msg_count,
               msg_time,
               keys->keyentries[id]->local,
               keys->keyentries[id]->global);

        merror(ENCTIME_ERROR, keys->keyentries[id]->name);
        w_mutex_unlock(&keys->keyentries[id]->mutex);
        return KS_RIDS;
    }
    mwarn(ENCKEY_ERROR, keys->keyentries[id]->id, srcip);
    return KS_ENCKEY;
}

/* Create an encrypted message
 * Returns the size
 */
size_t CreateSecMSG(const keystore *keys, const char *msg, size_t msg_length, char *msg_encrypted, unsigned int id)
{
    size_t bfsize;
    size_t length;
    unsigned long int cmp_size;
    u_int16_t rand1;
    char _tmpmsg[OS_MAXSTR + 2];
    char _finmsg[OS_MAXSTR + 2];
    char crypto_token[6] = {0};
    unsigned long crypto_length = 0;
    int crypto_method = 0;
    os_md5 md5sum;
    time_t curr_time;

    /* Check for invalid msg sizes */
    if ((msg_length > (OS_MAXSTR - OS_HEADER_SIZE)) || (msg_length < 1)) {
        curr_time = time(0);
        if (curr_time - saved_time > 3600) {
            merror("Incorrect message size: %lu", (unsigned long)msg_length);
            saved_time = curr_time;
        }
        mdebug2(ENCSIZE_ERROR, msg);
        return (0);
    }

    crypto_method = keys->keyentries[id]->crypto_method;

    switch(crypto_method)
    {
        case W_METH_BLOWFISH:
            memcpy(crypto_token,":",1);
            break;
        case W_METH_AES:
            memcpy(crypto_token,"#AES:",5);
            break;
        default:
            return OS_INVALID;
    }

    /* Random number, take only 5 chars ~= 2^16=65536*/
    rand1 = (u_int16_t) os_random();

    _tmpmsg[OS_MAXSTR + 1] = '\0';
    _finmsg[OS_MAXSTR + 1] = '\0';
    msg_encrypted[OS_MAXSTR] = '\0';

    w_mutex_lock(&keys->keyentries[keys->keysize]->mutex);
    ReloadCounter(keys, keys->keysize, SENDER_COUNTER);

    /* Increase local and global counters */
    if (local_count >= 9997) {
        local_count = 0;
        global_count++;
    }
    local_count++;

    length = snprintf(_tmpmsg, OS_MAXSTR, "%05hu%010u:%04u:", rand1, global_count, local_count);
    memcpy(_tmpmsg + length, msg, msg_length);
    length += msg_length;

    /* Generate MD5 of the unencrypted string */
    OS_MD5_Str(_tmpmsg, length, md5sum);

    /* Generate final msg to be compressed: <md5sum><_tmpmsg> */
    strcpy(_finmsg, md5sum);
    memcpy(_finmsg + 32, _tmpmsg, length);
    length += 32;

    /* Compress the message
     * We assign the first 8 bytes for padding
     */
    cmp_size = os_zlib_compress(_finmsg, _tmpmsg + 8, length, OS_MAXSTR - 12);
    if (!cmp_size) {
        merror(COMPRESS_ERR, _finmsg);
        w_mutex_unlock(&keys->keyentries[keys->keysize]->mutex);
        return (0);
    }
    cmp_size++;

    /* Pad the message (needs to be div by 8) */
    bfsize = 8 - (cmp_size % 8);
    if (bfsize == 8) {
        bfsize = 0;
    }

    _tmpmsg[0] = '!';
    _tmpmsg[1] = '!';
    _tmpmsg[2] = '!';
    _tmpmsg[3] = '!';
    _tmpmsg[4] = '!';
    _tmpmsg[5] = '!';
    _tmpmsg[6] = '!';
    _tmpmsg[7] = '!';

    cmp_size += bfsize;

    /* Get average sizes */
    c_orig_size += length;
    c_comp_size += cmp_size;
    if (evt_count > _s_comp_print) {
        mdebug1("Event count after '%u': %lu->%lu (%lu%%)",
                evt_count,
                (unsigned long)c_orig_size,
                (unsigned long)c_comp_size,
                (unsigned long)((c_comp_size * 100) / c_orig_size));
        evt_count = 0;
        c_orig_size = 0;
        c_comp_size = 0;
    }
    evt_count++;

    /* If the IP is dynamic (not single host), append agent ID to the message */
    if (!isSingleHost(keys->keyentries[id]->ip) && isAgent) {
        length = snprintf(msg_encrypted, 16, "!%s!%s", keys->keyentries[id]->id,crypto_token);
    } else {
        /* Set beginning of the message */
        length = snprintf(msg_encrypted, 6, "%s",crypto_token);
    }

    /* length is the amount of non-encrypted message appended to the buffer
     * On dynamic IPs, it will include the agent ID
     */
    /* Encrypt everything */
    crypto_length = doEncryptByMethod(_tmpmsg + (7 - bfsize), msg_encrypted + length,
        keys->keyentries[id]->key,
        (long) cmp_size,
        OS_ENCRYPT,crypto_method);

    /* Store before leaving */
    StoreSenderCounter(keys, global_count, local_count);
    w_mutex_unlock(&keys->keyentries[keys->keysize]->mutex);

    if(cmp_size < crypto_length)
        cmp_size = crypto_length;

    return (cmp_size + length);
}
