/* @(#) $Id$ */

/* Copyright (C) 2010 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Read the Linux audit log files */

#ifndef WIN32

#include "shared.h"
#include "logcollector.h"

#ifdef BUILD_TEST_BINARY
#define SendMSG(q, b, f, Q) printf("%s\n", b)
// #define SendMSG(q, b, f, Q)    1
#define debug1(...)            {};
#define debug2(...)            {};
#define merror                 printf
#define ErrorExit(a,b,c)       exit(1)
#undef ARGV0
#define ARGV0                  "test"
#undef os_calloc
#define os_calloc(n, s, p)     { p = calloc(n, s); }
#define TEST_LOG               "test_audit.log"
#define MAX_COPY_LINES         20
#endif /* BUILD_TEST_BINARY */

typedef struct _log_record {
    long lrid;
    int is_timeout; // is counter timeout or window
    int counter;
    char buffer[OS_MAXSTR+1];
} log_record;

//    OSList *log_records;

void _decrement_every_timeout_or_window(int pos)
{
    OSList *log_records = (OSList *)(logff[pos].private_data);

    OSListNode *n = OSList_GetFirstNode(log_records);

    while (n) {

        log_record *lr = (log_record *)n->data;
        lr->counter--;

        n = OSList_GetNextNode(log_records);
    }
}

void _send_msg(int pos, log_record *lr)
{
    if(SendMSG(logr_queue, lr->buffer, logff[pos].file, LOCALFILE_MQ) < 0)
    {
        merror(QUEUE_SEND, ARGV0);
        if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
        }
    }
}

void _send_expired_items(int pos)
{
    OSList *log_records = (OSList *)(logff[pos].private_data);

    OSListNode *n = OSList_GetFirstNode(log_records);

    while (n) {

        log_record *lr = (log_record *)n->data;

        if (lr->counter == 0) {

            _send_msg(pos, lr);
            os_free(lr);
            OSList_DeleteThisNode(log_records, n);
            n = OSList_GetCurrentlyNode(log_records);
        } else
            n = OSList_GetNextNode(log_records);
    }
}

log_record *_get_or_create_lr_by_id(int pos, long lrid)
{
    OSList *log_records = (OSList *)(logff[pos].private_data);
    log_record *lr;

    OSListNode *n = OSList_GetFirstNode(log_records);

    while (n) {

        lr = (log_record *)n->data;

        if (lr->lrid == lrid)
            return lr;

        n = OSList_GetNextNode(log_records);
    }

    os_calloc(1, sizeof(log_record), lr);
    memset(lr, sizeof(log_record), 0);

    lr->lrid = lrid;

    // Just in case...
    lr->buffer[0] = '\0';
    lr->buffer[OS_MAXSTR] = '\0';

    lr->is_timeout = (logff[pos].timeout != 0);
    if (lr->is_timeout)
        lr->counter = logff[pos].timeout;
    else
        lr->counter = logff[pos].window;

    if (OSList_AddData(log_records, lr) != 1)
        // Fail miserably
        exit(1);

    return lr;
}

int read_linux_audit_init(int pos)
{
    if ((logff[pos].private_data = OSList_Create()) == NULL)
        exit(1);

    // We should be called in each iteration no matter if the
    // log file was written to, or not, for housekeeping tasks...
    logff[pos].flags |= LOGREADER_FLAG_TIMERS;

    return 1;
}

/* Read Linux audit log file. */
int read_linux_audit(int pos, int drop_it)
{
    int __ms = 0;
    int buffer_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    str[OS_MAXSTR]= '\0';

    fpos_t fp_pos;

    // Start by decrementing all window/timeout values
    _decrement_every_timeout_or_window(pos);

    /* Getting initial file location */
    fgetpos(logff[pos].fp, &fp_pos);

    while(fgets(str, OS_MAXSTR - OS_LOG_HEADER, logff[pos].fp) != NULL)
    {

        /* Getting the last occurence of \n */
        if ((p = strrchr(str, '\n')) != NULL) 
        {
            *p = '\0';
        }

        /* If we didn't get the new line, because the
         * size is large, send what we got so far.
         */
        else if(strlen(str) >= (OS_MAXSTR - OS_LOG_HEADER - 2))
        {
            /* Message size > maximum allowed */
            __ms = 1;
        }
        else
        {
            /* Message not complete. Return. */
            debug1("%s: Message not complete. Trying again: '%s'", ARGV0,str);
            fsetpos(logff[pos].fp, &fp_pos);
            break;
        }    

        debug2("%s: DEBUG: Reading message: '%s'", ARGV0, str);
        
        // Extract log record ID.
        // Search for first occurence of :, after that, up to the closing
        // bracket is the ID.
        char *s;
        if ((s = strchr(str, ':')) == NULL) {
            merror("%s: Ignoring line with no record ID: '%s'", ARGV0, str);
            continue;
        }

        int lrid = atoi(++s);
        if (lrid == 0) {
            merror("%s: Ignoring line with no record ID: '%s'", ARGV0, str);
            continue;
        }

        log_record *lr = _get_or_create_lr_by_id(pos, lrid);
        if (lr == NULL) {
            merror("%s: Unknown error: '%s'", ARGV0, str);
            continue;
        }

        // We touched the record, refresh timeout if used...
        if (lr->is_timeout)
            lr->counter = logff[pos].timeout;

        /* Adding to buffer. */
        buffer_size = strlen(lr->buffer);
        if(lr->buffer[0] != '\0')
        {
            // Convert NULL to space, we are not using strcat...
            lr->buffer[buffer_size] = ' ';
            buffer_size++;
        }

        // We don't treat specially buffer overflow but count on being
        // properly handled as a side effect of regular processing (sic!)
        strncpy(lr->buffer + buffer_size, str, OS_MAXSTR - buffer_size -2);

        /* Incorrectly message size */
        if(__ms)
        {

            merror("%s: Large message size: '%s'", ARGV0, str);
            while(fgets(str, OS_MAXSTR - 2, logff[pos].fp) != NULL)
            {
                /* Getting the last occurence of \n */
                if ((p = strrchr(str, '\n')) != NULL)
                {
                    break;
                }
            }
            __ms = 0;
        }
        
        fgetpos(logff[pos].fp, &fp_pos);
    }

    // Now look for all log records that have zero in counter and send them
    // to the central location
    if(drop_it == 0)
        _send_expired_items(pos);

    return 0; 
}

#ifdef BUILD_TEST_BINARY
int main(int argc, char **argv)
{
    FILE *inf, *outf;
    char buffer[OS_MAXSTR+1];
    int timeout = 0, window = 0;

    int rc;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s timeout window <audit log file>\n", argv[0]);
        return 1;
    }

    timeout = atoi(argv[1]);
    window = atoi(argv[2]);

    if ((inf = fopen(argv[3], "r")) == NULL) {
        perror("fopen");
        return 1;
    }

    if ((outf = fopen(TEST_LOG, "w")) == NULL) {
        perror("fopen");
        return 1;
    }

    os_calloc(1, sizeof(logreader), logff);

    logff[0].file = TEST_LOG;
    logff[0].fp = fopen(logff[0].file, "r");
    logff[0].timeout = timeout;
    logff[0].window = window;

    read_linux_audit_init(0);
    while (!feof(inf)) {

        // First, copy a random number of lines from real log to test log
        int n = rand() % MAX_COPY_LINES;
        while(n-- > 0 && fgets(buffer, OS_MAXSTR, inf) != NULL)
             fputs(buffer, outf);

        // Now call routine to be tested
        rc = read_linux_audit(0, 0);

//     sleep(1);
    }

    // To flush what's left waiting...
    while (timeout > 0 && window > 0) {
        if (timeout > 0) timeout--;
        if (window > 0) window--;
        rc = read_linux_audit(0, 0);
    }
    
    return 0;
}
#endif /* BUILD_TEST_BINARY */

#endif /* !WIN32 */

/* EOF */

