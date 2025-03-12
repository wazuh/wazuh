/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Read MySQL logs */

#include "shared.h"
#include "logcollector.h"
#include "os_crypto/sha1/sha1_op.h"

/* Starting last time */
static char __mysql_last_time[36] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};


void *read_mysql_log(logreader *lf, int *rc, int drop_it) {
    size_t str_len = 0;
    int need_clear = 0;
    char *p;
    char str[OS_MAX_LOG_SIZE] = {0};
    char buffer[OS_MAX_LOG_SIZE] = {0};
    int lines = 0;
    int bytes_written = 0;

    *rc = 0;

    /* Obtain context to calculate hash */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    int64_t current_position = w_ftell(lf->fp);
    bool is_valid_context_file = w_get_hash_context(lf, &context, current_position);

    /* Get new entry */
    while (can_read() && (!maximum_lines || lines < maximum_lines) && fgets(str, sizeof(str), lf->fp)) {

        lines++;
        /* Get buffer size */
        str_len = strlen(str);

        if (is_valid_context_file) {
            OS_SHA1_Stream(context, NULL, str);
        }

        /* Get the last occurrence of \n */
        if ((p = strrchr(str, '\n')) != NULL) {
            *p = '\0';

            /* If need clear is set, we just get the line and ignore it */
            if (need_clear) {
                need_clear = 0;
                continue;
            }
        } else {
            need_clear = 1;
        }

#ifdef WIN32
        if ((p = strrchr(str, '\r')) != NULL) {
            *p = '\0';
        }

        /* Look for empty string (only on windows) */
        if (str_len <= 2) {
            continue;
        }


        /* Windows can have comment on their logs */
        if (str[0] == '#') {
            continue;
        }
#endif

        /* MySQL messages have the following format:
         * 070823 21:01:30 xx
         */
        if ((str_len > 18) &&
                (str[6] == ' ') &&
                (str[9] == ':') &&
                (str[12] == ':') &&
                isdigit((int)str[0]) &&
                isdigit((int)str[1]) &&
                isdigit((int)str[2]) &&
                isdigit((int)str[3]) &&
                isdigit((int)str[4]) &&
                isdigit((int)str[5]) &&
                isdigit((int)str[7]) &&
                isdigit((int)str[8])) {
            /* Save last time */
            strncpy(__mysql_last_time, str, 16);
            __mysql_last_time[15] = '\0';


            /* Remove spaces and tabs */
            p = str + 15;
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Valid MySQL message */
            bytes_written = snprintf(buffer, sizeof(buffer), "MySQL log: %s %s",
                     __mysql_last_time, p);
        }

       /* MySQL 5.7 messages have the following format(in case of NOT utc):
        * YYYY-MM-DDThh:mm:ss.uuuuuu±hh:mm XX
        * ref: https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_log_timestamps
        */
       else if ((str_len > 35) &&
               (str[4] == '-') &&
               (str[7] == '-') &&
               (str[10] == 'T') &&
               (str[13] == ':') &&
               (str[16] == ':') &&
               (str[19] == '.') &&
               ((str[26] == '-') || (str[26] == '+')) &&
               (str[29] == ':') &&
               (str[32] == ' ') &&
               isdigit((int)str[0]) &&
               isdigit((int)str[1]) &&
               isdigit((int)str[2]) &&
               isdigit((int)str[3]) &&
               isdigit((int)str[5]) &&
               isdigit((int)str[6]) &&
               isdigit((int)str[8]) &&
               isdigit((int)str[9]) &&
               isdigit((int)str[11]) &&
               isdigit((int)str[12]) &&
               isdigit((int)str[14]) &&
               isdigit((int)str[15]) &&
               isdigit((int)str[17]) &&
               isdigit((int)str[18]) &&
               isdigit((int)str[20]) &&
               isdigit((int)str[21]) &&
               isdigit((int)str[22]) &&
               isdigit((int)str[23]) &&
               isdigit((int)str[24]) &&
               isdigit((int)str[25]) &&
               isdigit((int)str[27]) &&
               isdigit((int)str[28]) &&
               isdigit((int)str[30]) &&
               isdigit((int)str[31])) {
           /* Save last time */
           strncpy(__mysql_last_time, str, 33);
           __mysql_last_time[32] = '\0';

           /* Remove spaces and tabs */
           p = str + 32;
           while (*p == ' ' || *p == '\t') {
               p++;
           }

           /* Valid MySQL message */
           bytes_written = snprintf(buffer, sizeof(buffer), "MySQL log: %s %s",
                    __mysql_last_time, p);
       }

      /* MySQL 5.7 messages have the following format(in case of utc):
       * YYYY-MM-DDThh:mm:ss.uuuuuuZ XX
       * ref: https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_log_timestamps
       */
      else if ((str_len > 30) &&
              (str[4] == '-') &&
              (str[7] == '-') &&
              (str[10] == 'T') &&
              (str[13] == ':') &&
              (str[16] == ':') &&
              (str[19] == '.') &&
              (str[26] == 'Z') &&
              (str[27] == ' ') &&
              isdigit((int)str[0]) &&
              isdigit((int)str[1]) &&
              isdigit((int)str[2]) &&
              isdigit((int)str[3]) &&
              isdigit((int)str[5]) &&
              isdigit((int)str[6]) &&
              isdigit((int)str[8]) &&
              isdigit((int)str[9]) &&
              isdigit((int)str[11]) &&
              isdigit((int)str[12]) &&
              isdigit((int)str[14]) &&
              isdigit((int)str[15]) &&
              isdigit((int)str[17]) &&
              isdigit((int)str[18]) &&
              isdigit((int)str[20]) &&
              isdigit((int)str[21]) &&
              isdigit((int)str[22]) &&
              isdigit((int)str[23]) &&
              isdigit((int)str[24]) &&
              isdigit((int)str[25])) {
          /* Save last time */
          strncpy(__mysql_last_time, str, 28);
          __mysql_last_time[27] = '\0';

          /* Remove spaces and tabs */
          p = str + 27;
          while (*p == ' ' || *p == '\t') {
              p++;
          }

          /* Valid MySQL message */
          bytes_written = snprintf(buffer, sizeof(buffer), "MySQL log: %s %s",
                   __mysql_last_time, p);
      }

        /* Multiple events at the same second share the same timestamp:
         * 0909 2020 2020 2020 20
         */
        else if ((str_len > 10) && (__mysql_last_time[0] != '\0') &&
                 (str[0] == 0x09) &&
                 (str[1] == 0x09) &&
                 (str[2] == 0x20) &&
                 (str[3] == 0x20) &&
                 (str[4] == 0x20) &&
                 (str[5] == 0x20) &&
                 (str[6] == 0x20) &&
                 (str[7] == 0x20)) {
            p = str + 2;

            /* Remove extra spaces and tabs */
            while (*p == ' ' || *p == '\t') {
                p++;
            }

            /* Valid MySQL message */
            bytes_written = snprintf(buffer, sizeof(buffer), "MySQL log: %s %s",
                     __mysql_last_time, p);
        } else {
            continue;
        }

        if (bytes_written < 0) {
            merror("Error %d (%s) while reading message: '%s' (length = " FTELL_TT "): '%s'...", errno, strerror(errno), lf->file, FTELL_INT64 bytes_written, buffer);
        } else if ((size_t)bytes_written >= sizeof(buffer)) {
            merror("Message size too big on file '%s' (length = " FTELL_TT "): '%s'...", lf->file, FTELL_INT64 bytes_written, buffer);
        }

        mdebug2("Reading mysql messages: '%s'", buffer);

        /* Check ignore and restrict log regex, if configured. */
        if (drop_it == 0 && !check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, buffer)) {
            /* Send message to queue */
            w_msg_hash_queues_push(buffer, lf->file, strlen(buffer) + 1, lf->log_target, LOCALFILE_MQ);
        }
    }

    current_position = w_ftell(lf->fp);

    if (is_valid_context_file) {
        w_update_file_status(lf->file, current_position, context);
    } else {
        EVP_MD_CTX_free(context);
    }

    mdebug2("Read %d lines from %s", lines, lf->file);
    return (NULL);
}
