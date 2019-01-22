/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "os_net/os_net.h"
#include "agentd.h"

#ifndef WIN32
static time_t g_saved_time = 0;
static char *rand_keepalive_str2(char *dst, int size);

static char *rand_keepalive_str2(char *dst, int size)
{
    static const char text[] = "abcdefghijklmnopqrstuvwxyz"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "0123456789"
                               "!@#$%^&*()_+-=;'[],./?";
    int i;
    int len;

    srandom_init();
    len = os_random() % (size - 1);
    len = len >= 0 ? len : -len;

    for ( i = 0; i < len; ++i ) {
        dst[i] = text[(unsigned)os_random() % (sizeof text - 1)];
    }
    dst[i] = '\0';
    return dst;
}
#endif

/* Return the names of the files in a directory */
char *getsharedfiles()
{
    unsigned int m_size = 512;
    char *ret;
    os_md5 md5sum;

    if (OS_MD5_File(SHAREDCFG_FILE, md5sum, OS_TEXT) != 0) {
        md5sum[0] = 'x';
        md5sum[1] = '\0';
    }

    /* We control these files, max size is m_size */
    ret = (char *)calloc(m_size + 1, sizeof(char));
    if (!ret) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (NULL);
    }

    snprintf(ret, m_size, "%s merged.mg\n", md5sum);

    return (ret);
}

#ifndef WIN32

/* Periodically send notification to server */
void run_notify()
{
    char keep_alive_random[KEEPALIVE_SIZE];
    char tmp_msg[OS_MAXSTR - OS_HEADER_SIZE];
    static char tmp_labels[OS_MAXSTR - OS_HEADER_SIZE] = { '\0' };
    char *shared_files;
    os_md5 md5sum;
    time_t curr_time;

    keep_alive_random[0] = '\0';
    curr_time = time(0);

#ifndef ONEWAY_ENABLED
    /* Check if the server has responded */
    if ((curr_time - available_server) > agt->max_time_reconnect_try) {
        /* If response is not available, set lock and wait for it */
        mwarn(SERVER_UNAV);
        os_setwait();
        update_status(GA_STATUS_NACTIVE);

        /* Send sync message */
        start_agent(0);

        minfo(SERVER_UP);
        os_delwait();
        update_status(GA_STATUS_ACTIVE);
    }
#endif

    /* Check if time has elapsed */
    if ((curr_time - g_saved_time) < agt->notify_time) {
        return;
    }
    g_saved_time = curr_time;

    mdebug1("Sending agent notification.");

    /* Send the message
     * Message is going to be the uname\n checksum file\n checksum file\n
     */

    /* Get uname */
    if (!getuname()) {
        merror(MEM_ERROR, errno, strerror(errno));
    }

    /* Format labeled data */

    if (!tmp_labels[0] && labels_format(agt->labels, tmp_labels, OS_MAXSTR - OS_HEADER_SIZE) < 0) {
        merror("Too large labeled data.");
        tmp_labels[0] = '\0';
    }

    /* Get shared files */
    shared_files = getsharedfiles();
    if (!shared_files) {
        shared_files = strdup("\0");
        if (!shared_files) {
            merror(MEM_ERROR, errno, strerror(errno));
            return;
        }
    }

    rand_keepalive_str2(keep_alive_random, KEEPALIVE_SIZE);

    /* Create message */
    if ((File_DateofChange(AGENTCONFIGINT) > 0 ) &&
            (OS_MD5_File(AGENTCONFIGINT, md5sum, OS_TEXT) == 0)) {
        snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "#!-%s / %s\n%s%s\n%s",
                 getuname(), md5sum, tmp_labels, shared_files, keep_alive_random);
    } else {
        snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "#!-%s\n%s%s\n%s",
                 getuname(), tmp_labels, shared_files, keep_alive_random);
    }

    /* Send status message */
    mdebug2("Sending keep alive: %s", tmp_msg);
    send_msg(tmp_msg, -1);

    free(shared_files);
    update_keepalive(curr_time);
    return;
}
#endif /* !WIN32 */
