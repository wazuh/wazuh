/* @(#) $Id$ */

/* Copyright (C) 2005-2008 Third Brigade, Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>


#ifdef USEINOTIFY
#include <sys/inotify.h>
#endif

#include "hash_op.h"
#include "debug_op.h"
#include "syscheck.h"

#define REALTIME_MONITOR_FLAGS  IN_MODIFY|IN_ATTRIB
#define REALTIME_EVENT_SIZE     (sizeof (struct inotify_event))
#define REALTIME_EVENT_BUFFER   (2048 * (REALTIME_EVENT_SIZE + 16))

int c_read_file(char *file_name, char *oldsum, char *newsum);



/* Starts real time monitoring using inotify. */
int realtime_start()
{
    verbose("%s: INFO: Initializing real time file monitoring (not started).", ARGV0);

    syscheck.realtime = calloc(1, sizeof(rtfim));
    syscheck.realtime->dirtb = (void *)OSHash_Create();
    syscheck.realtime->fd = -1;

    #ifdef USEINOTIFY
    syscheck.realtime->fd = inotify_init();
    if(syscheck.realtime->fd < 0)
    {
        merror("%s: ERROR: Unable to initialize inotify.", ARGV0);
        return(-1);
    }
    #endif    

    return(1);
}



/* Adds a directory to real time checking. */
int realtime_adddir(char *dir)
{
    if(!syscheck.realtime)
    {
        realtime_start();
    }


    /* Checking if it is ready to use. */
    if(syscheck.realtime->fd < 0)
    {
        return(-1);
    }
    else
    {

        #ifdef USEINOTIFY
        int wd = 0;

        wd = inotify_add_watch(syscheck.realtime->fd,
                               dir,
                               REALTIME_MONITOR_FLAGS); 
        if(wd < 0)
        {
            merror("%s: ERROR: Unable to add directory to real time " 
                   "monitoring: '%s'.", ARGV0, dir);
        }
        else
        {
            char wdchar[32 +1];
            wdchar[32] = '\0';
            snprintf(wdchar, 32, "%d", wd);

            /* Entry not present. */
            if(!OSHash_Get(syscheck.realtime->dirtb, wdchar))
            {
                OSHash_Add(syscheck.realtime->dirtb, strdup(wdchar), dir);
                debug1("%s: DEBUG: Directory added for real time monitoring: "
                       "'%s'.", ARGV0, dir);
            }
        }
        #endif

    }

    return(1);
}


/* Checking sum of the realtime file being monitored. */
int realtime_checksumfile(char *file_name)
{
    char buf[MAX_LINE +2];
    buf[MAX_LINE +1] = '\0';

    fseek(syscheck.fp, 0, SEEK_SET);
    while(fgets(buf, MAX_LINE, syscheck.fp) != NULL)
    {
        if((buf[0] != '#') && (buf[0] != ' ') && (buf[0] != '\n'))
        {
            char *n_buf;

            /* Removing the new line */
            n_buf = strchr(buf,'\n');
            if(n_buf == NULL)
                continue;

            *n_buf = '\0';


            /* First 6 characters are for internal use */
            n_buf = buf;
            n_buf+=6;

            n_buf = strchr(n_buf, ' ');
            if(n_buf)
            {
                n_buf++;

                /* Checking if name matches */
                if(strcmp(n_buf, file_name) == 0)
                {
                    char c_sum[256 +2];
                    c_sum[0] = '\0';
                    c_sum[255] = '\0';


                    /* If it returns < 0, we will already have alerted. */
                    if(c_read_file(file_name, buf, c_sum) < 0)
                        continue;


                    if(strcmp(c_sum, buf+6) != 0)
                    {
                        char alert_msg[912 +2];

                        /* Sending the new checksum to the analysis server */
                        alert_msg[912 +1] = '\0';
                        snprintf(alert_msg, 912, "%s %s", c_sum, file_name);
                        send_syscheck_msg(alert_msg);

                        return(1);
                    }

                    return(0);

                }
            }
        }
    }

    /* Adding entry if not in there. */
    fseek(syscheck.fp, 0, SEEK_END);
    return(0);
}


/* Process events in the real time queue. */
int realtime_process()
{
    int len, i = 0;
    char buf[REALTIME_EVENT_BUFFER +1];
    struct inotify_event *event;

    buf[REALTIME_EVENT_BUFFER] = '\0';


    len = read(syscheck.realtime->fd, buf, REALTIME_EVENT_BUFFER);
    if (len < 0) 
    {
        merror("%s: ERROR: Unable to read from real time buffer.", ARGV0);
    } 
    else if (len > 0)
    {
        while (i < len) 
        {
            event = (struct inotify_event *) &buf[i];

            if(event->len)
            {
                char wdchar[32 +1];
                char final_name[MAX_LINE +1];

                wdchar[32] = '\0';
                final_name[MAX_LINE] = '\0';

                snprintf(wdchar, 32, "%d", event->wd);

                snprintf(final_name, MAX_LINE, "%s/%s", 
                         (char *)OSHash_Get(syscheck.realtime->dirtb, wdchar),
                         event->name);
                realtime_checksumfile(final_name);
            }

            i += REALTIME_EVENT_SIZE + event->len;
        }
    }

    return(0);
}

/* EOF */
