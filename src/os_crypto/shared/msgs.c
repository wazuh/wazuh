/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "headers/sec.h"
#include "os_zlib/os_zlib.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/blowfish/bf_op.h"

/* Prototypes */
static void StoreSenderCounter(const keystore *keys, unsigned int global, unsigned int local) __attribute((nonnull));
static void StoreCounter(const keystore *keys, int id, unsigned int global, unsigned int local) __attribute((nonnull));
static char *CheckSum(char *msg) __attribute((nonnull));

/* Sending counts */
static unsigned int global_count = 0;
static unsigned int local_count  = 0;

/* Average compression rates */
static unsigned int evt_count = 0;
static unsigned int rcv_count = 0;
static size_t c_orig_size = 0;
static size_t c_comp_size = 0;

/* Static variables (read from define file) */
static unsigned int _s_comp_print = 0;
static unsigned int _s_recv_flush = 0;

static int _s_verify_counter = 1;


/* Read counters for each agent */
void OS_StartCounter(keystore *keys)
{
    unsigned int i;
    char rids_file[OS_FLSIZE + 1];

    rids_file[OS_FLSIZE] = '\0';

    debug1("%s: OS_StartCounter: keysize: %u", __local_name, keys->keysize);

    /* Start receiving counter */
    for (i = 0; i <= keys->keysize; i++) {
        /* On i == keysize, we deal with the sender counter */
        if (i == keys->keysize) {
            snprintf(rids_file, OS_FLSIZE, "%s/%s",
                     RIDS_DIR,
                     SENDER_COUNTER);
        } else {
            snprintf(rids_file, OS_FLSIZE, "%s/%s",
                     RIDS_DIR,
                     keys->keyentries[i]->id);
        }

        keys->keyentries[i]->fp = fopen(rids_file, "r+");

        /* If nothing is there, try to open as write only */
        if (!keys->keyentries[i]->fp) {
            keys->keyentries[i]->fp = fopen(rids_file, "w");
            if (!keys->keyentries[i]->fp) {
                int my_error = errno;

                /* Just in case we run out of file descriptors */
                if ((i > 10) && (keys->keyentries[i - 1]->fp)) {
                    fclose(keys->keyentries[i - 1]->fp);

                    if (keys->keyentries[i - 2]->fp) {
                        fclose(keys->keyentries[i - 2]->fp);
                    }
                }

                merror("%s: Unable to open agent file. errno: %d",
                       __local_name, my_error);
                ErrorExit(FOPEN_ERROR, __local_name, rids_file, errno, strerror(errno));
            }
        } else {
            unsigned int g_c = 0, l_c = 0;
            if (fscanf(keys->keyentries[i]->fp, "%u:%u", &g_c, &l_c) != 2) {
                if (i == keys->keysize) {
                    verbose("%s: INFO: No previous sender counter.", __local_name);
                } else {
                    verbose("%s: INFO: No previous counter available for '%s'.",
                            __local_name,
                            keys->keyentries[i]->name);
                }

                g_c = 0;
                l_c = 0;
            }

            if (i == keys->keysize) {
                verbose("%s: INFO: Assigning sender counter: %u:%u",
                        __local_name, g_c, l_c);
                global_count = g_c;
                local_count = l_c;
            } else {
                verbose("%s: INFO: Assigning counter for agent %s: '%u:%u'.",
                        __local_name, keys->keyentries[i]->name, g_c, l_c);

                keys->keyentries[i]->global = g_c;
                keys->keyentries[i]->local = l_c;
            }
        }
    }

    debug2("%s: DEBUG: Stored counter.", __local_name);

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
}

/* Store the global and local count of events */
static void StoreCounter(const keystore *keys, int id, unsigned int global, unsigned int local)
{
    /* Write to the beginning of the file */
    fseek(keys->keyentries[id]->fp, 0, SEEK_SET);
    fprintf(keys->keyentries[id]->fp, "%u:%u:", global, local);
}

/* Verify the checksum of the message
 * Returns NULL on error or the message on success
 */
static char *CheckSum(char *msg)
{
    os_md5 recvd_sum;
    os_md5 checksum;

    /* Better way */
    strncpy(recvd_sum, msg, 32);
    recvd_sum[32] = '\0';

    msg += 32;

    OS_MD5_Str(msg, checksum);
    if (strncmp(checksum, recvd_sum, 32) != 0) {
        return (NULL);
    }

    return (msg);
}

char *ReadSecMSG(keystore *keys, char *buffer, char *cleartext,
                 int id, unsigned int buffer_size)
{
    unsigned int msg_global = 0;
    unsigned int msg_local = 0;
    char *f_msg;

    if (*buffer == ':') {
        buffer++;
    } else {
        merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
        return (NULL);
    }

    /* Decrypt message */
    if (!OS_BF_Str(buffer, cleartext, keys->keyentries[id]->key,
                   buffer_size, OS_DECRYPT)) {
        merror(ENCKEY_ERROR, __local_name, keys->keyentries[id]->ip->ip);
        return (NULL);
    }

    /* Compressed */
    else if (cleartext[0] == '!') {
        cleartext[buffer_size] = '\0';
        cleartext++;
        buffer_size--;

        /* Remove padding */
        while (*cleartext == '!') {
            cleartext++;
            buffer_size--;
        }

        /* Uncompress */
        if (!os_zlib_uncompress(cleartext, buffer, buffer_size, OS_MAXSTR)) {
            merror(UNCOMPRESS_ERR, __local_name);
            return (NULL);
        }

        /* Check checksum */
        f_msg = CheckSum(buffer);
        if (f_msg == NULL) {
            merror(ENCSUM_ERROR, __local_name, keys->keyentries[id]->ip->ip);
            return (NULL);
        }

        /* Remove random */
        f_msg += 5;

        /* Check count -- protect against replay attacks */
        msg_global = (unsigned int) atoi(f_msg);
        f_msg += 10;

        /* Check for the right message format */
        if (*f_msg != ':') {
            merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
            return (NULL);
        }
        f_msg++;

        msg_local = (unsigned int) atoi(f_msg);
        f_msg += 5;

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
            return (f_msg);
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
            return (f_msg);
        }

        /* Check if it is a duplicated message */
        if (msg_global == keys->keyentries[id]->global) {
            return (NULL);
        }

        /* Warn about duplicated messages */
        merror("%s: WARN: Duplicate error:  global: %u, local: %u, "
               "saved global: %u, saved local:%u",
               __local_name,
               msg_global,
               msg_local,
               keys->keyentries[id]->global,
               keys->keyentries[id]->local);

        merror(ENCTIME_ERROR, __local_name, keys->keyentries[id]->name);
        return (NULL);
    }

    /* Old format */
    else if (cleartext[0] == ':') {
        unsigned int msg_count;
        unsigned int msg_time;

        /* Close string */
        cleartext[buffer_size] = '\0';

        /* Check checksum */
        cleartext++;
        f_msg = CheckSum(cleartext);
        if (f_msg == NULL) {
            merror(ENCSUM_ERROR, __local_name, keys->keyentries[id]->ip->ip);
            return (NULL);
        }

        /* Check time -- protect against replay attacks */
        msg_time = (unsigned int) atoi(f_msg);
        f_msg += 11;

        msg_count = (unsigned int) atoi(f_msg);
        f_msg += 5;


        /* Return the message if we don't need to verify the counter */
        if (!_s_verify_counter) {
            /* Update current counts */
            keys->keyentries[id]->global = msg_time;
            keys->keyentries[id]->local = msg_local;

            f_msg = strchr(f_msg, ':');
            if (f_msg) {
                f_msg++;
                return (f_msg);
            } else {
                merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
                return (NULL);
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
                return (f_msg);
            } else {
                merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
                return (NULL);
            }
        }

        /* Check if it is a duplicated message */
        if ((msg_count == keys->keyentries[id]->local) &&
                (msg_time == keys->keyentries[id]->global)) {
            return (NULL);
        }

        /* Warn about duplicated message */
        merror("%s: WARN: Duplicate error:  msg_count: %u, time: %u, "
               "saved count: %u, saved_time:%u",
               __local_name,
               msg_count,
               msg_time,
               keys->keyentries[id]->local,
               keys->keyentries[id]->global);

        merror(ENCTIME_ERROR, __local_name, keys->keyentries[id]->name);
        return (NULL);
    }

    merror(ENCFORMAT_ERROR, __local_name, keys->keyentries[id]->ip->ip);
    return (NULL);
}

/* Create an encrypted message
 * Returns the size
 */
size_t CreateSecMSG(const keystore *keys, const char *msg, char *msg_encrypted, unsigned int id)
{
    size_t bfsize;
    size_t msg_size;
    unsigned long int cmp_size;
    u_int16_t rand1;
    char _tmpmsg[OS_MAXSTR + 2];
    char _finmsg[OS_MAXSTR + 2];
    os_md5 md5sum;

    msg_size = strlen(msg);

    /* Check for invalid msg sizes */
    if ((msg_size > (OS_MAXSTR - OS_HEADER_SIZE)) || (msg_size < 1)) {
        merror(ENCSIZE_ERROR, __local_name, msg);
        return (0);
    }

    /* Random number, take only 5 chars ~= 2^16=65536*/
    rand1 = (u_int16_t) random();

    _tmpmsg[OS_MAXSTR + 1] = '\0';
    _finmsg[OS_MAXSTR + 1] = '\0';
    msg_encrypted[OS_MAXSTR] = '\0';

    /* Increase local and global counters */
    if (local_count >= 9997) {
        local_count = 0;
        global_count++;
    }
    local_count++;

    snprintf(_tmpmsg, OS_MAXSTR, "%05hu%010u:%04u:%s",
             rand1, global_count, local_count,
             msg);

    /* Generate MD5 of the unencrypted string */
    OS_MD5_Str(_tmpmsg, md5sum);

    /* Generate final msg to be compressed */
    snprintf(_finmsg, OS_MAXSTR, "%s%s", md5sum, _tmpmsg);
    msg_size = strlen(_finmsg);

    /* Compress the message
     * We assign the first 8 bytes for padding
     */
    cmp_size = os_zlib_compress(_finmsg, _tmpmsg + 8, msg_size, OS_MAXSTR - 12);
    if (!cmp_size) {
        merror(COMPRESS_ERR, __local_name, _finmsg);
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
    c_orig_size += msg_size;
    c_comp_size += cmp_size;
    if (evt_count > _s_comp_print) {
        verbose("%s: INFO: Event count after '%u': %lu->%lu (%lu%%)", __local_name,
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
        snprintf(msg_encrypted, 16, "!%s!:", keys->keyentries[id]->id);
        msg_size = strlen(msg_encrypted);
    } else {
        /* Set beginning of the message */
        msg_encrypted[0] = ':';
        msg_size = 1;
    }

    /* msg_size is the amount of non-encrypted message appended to the buffer
     * On dynamic IPs, it will include the agent ID
     */

    /* Encrypt everything */
    OS_BF_Str(_tmpmsg + (7 - bfsize), msg_encrypted + msg_size,
              keys->keyentries[id]->key,
              (long) cmp_size,
              OS_ENCRYPT);

    /* Store before leaving */
    StoreSenderCounter(keys, global_count, local_count);

    return (cmp_size + msg_size);
}

