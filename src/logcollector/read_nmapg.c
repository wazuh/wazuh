/* @(#) $Id: ./src/logcollector/read_nmapg.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "logcollector.h"


#define NMAPG_HOST  "Host: "
#define NMAPG_PORT  "Ports:"
#define NMAPG_OPEN  "open/"
#define NMAPG_STAT  "Status:"



/** Function Prototypes **/
static char *__go_after(char *x, const char *y);
static char *__get_port(char *str, char *proto, char *port, size_t msize);



/* Get port and protocol.
 */
static char *__get_port(char *str, char *proto, char *port, size_t msize)
{
    int filtered = 0;
    char *p, *q;


    /* Removing white spaces */
    while(*str == ' ')
    {
        str++;
    }


    /* Getting port */
    p = strchr(str, '/');
    if(!p)
        return(NULL);
    *p = '\0';
    p++;


    /* Getting port */
    strncpy(port, str, msize);
    port[msize -1] = '\0';



    /* Checking if the port is open */
    q = __go_after(p, NMAPG_OPEN);
    if(!q)
    {
        /* Port is not open */
        filtered = 1;
        q = p;


        /* Going to the start of protocol field */
        p = strchr(q, '/');
        if(!p)
            return(NULL);
        p++;
    }
    else
    {
        p = q;
    }



    /* Getting protocol */
    str = p;
    p = strchr(str, '/');
    if(!p)
    {
        return(NULL);
    }
    *p = '\0';
    p++;


    strncpy(proto, str, msize);
    proto[msize -1] = '\0';


    /* Setting proto to null if port is not open */
    if(filtered)
        proto[0] = '\0';


    /* Removing slashes */
    if(*p == '/')
    {
        p++;
        q = p;
        p = strchr(p, ',');
        if(p)
        {
            return(p);
        }

        return(q);
    }


    return(NULL);
}


/* Check if the string matches.
 */
static char *__go_after(char *x, const char *y)
{
    size_t x_s;
    size_t y_s;

    /* X and Y must be not null */
    if(!x || !y)
        return(NULL);

    x_s = strlen(x);
    y_s = strlen(y);

    if(x_s <= y_s)
    {
        return(NULL);
    }

    /* String does not match */
    if(strncmp(x,y,y_s) != 0)
    {
        return(NULL);
    }

    x+=y_s;

    return(x);
}


/* Read Nmap grepable files */
void *read_nmapg(int pos, int *rc, int drop_it)
{
    int final_msg_s;
    int need_clear = 0;

    char str[OS_MAXSTR + 1];
    char final_msg[OS_MAXSTR + 1];
    char buffer[OS_MAXSTR + 1];
    char port[17];
    char proto[17];

    char *ip = NULL;
    char *p;
    char *q;

    *rc = 0;
    str[OS_MAXSTR] = '\0';
    final_msg[OS_MAXSTR] = '\0';
    buffer[OS_MAXSTR] = '\0';

    port[16] = '\0';
    proto[16] = '\0';

    while(fgets(str, OS_MAXSTR -OS_LOG_HEADER, logff[pos].fp) != NULL)
    {
        /* If need clear is set, we need to clear the line */
        if(need_clear)
        {
            if((q = strchr(str, '\n')) != NULL)
            {
                need_clear = 0;
            }
            continue;
        }

        /* Removing \n at the end of the string */
        if ((q = strchr(str, '\n')) != NULL)
        {
            *q = '\0';
        }
        else
        {
            need_clear = 1;
        }


        /* Do not get commented lines */
        if((str[0] == '#') || (str[0] == '\0'))
        {
            continue;
        }


        /* Getting host */
        q = __go_after(str, NMAPG_HOST);
        if(!q)
        {
            goto file_error;
        }


        /* Getting ip/hostname */
        p = strchr(q, ')');
        if(!p)
        {
            goto file_error;
        }


        /* Setting the valid ip */
        ip = q;



        /* Getting the ports */
        q = strchr(p, '\t');
        if(!q)
        {
            goto file_error;
        }
        q++;


        /* Now fixing p, to have the closing parenthesis */
        p++;
        *p = '\0';


        /* q now should point to the ports */
        p = __go_after(q, NMAPG_PORT);
        if(!p)
        {
            /* Checking if no port is available */
            p = __go_after(q, NMAPG_STAT);
            if(p)
            {
                continue;
            }

            goto file_error;
        }


        /* Generating final msg */
        snprintf(final_msg, OS_MAXSTR, "Host: %s, open ports:",
                            ip);
        final_msg_s = OS_MAXSTR - ((strlen(final_msg) +3));


        /* Getting port and protocol */
        do
        {
            /* Avoid filling the buffer (3*port size). */
            if(final_msg_s < 27)
            {
                break;
            }

            p = __get_port(p, proto, port, 9);
            if(!p)
            {
                debug1("%s: Bad formatted nmap grepable file (port).", ARGV0);
                break;
            }


            /* Port not open */
            if(proto[0] == '\0')
            {
                continue;
            }


            /* Adding ports */
            snprintf(buffer, OS_MAXSTR, " %s(%s)", port, proto);
            strncat(final_msg, buffer, final_msg_s);
            final_msg_s-=(strlen(buffer) +2);

        }while(*p == ',' && (p++));


        if(drop_it == 0)
        {
            /* Sending message to queue */
            if(SendMSG(logr_queue, final_msg, logff[pos].file,
                        HOSTINFO_MQ) < 0)
            {
                merror(QUEUE_SEND, ARGV0);
                if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                {
                    ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);
                }
            }
        }


        /* Getting next */
        continue;


        /* Handling errors */
        file_error:

        merror("%s: Bad formatted nmap grepable file.", ARGV0);
        *rc = -1;
        return(NULL);

    }


    return(NULL);
}

/* EOF */
