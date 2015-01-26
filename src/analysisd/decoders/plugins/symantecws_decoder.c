/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "eventinfo.h"


void *SymantecWS_Decoder_Init()
{
    debug1("%s: Initializing SymantecWS decoder..", ARGV0);

    /* There is nothing to do over here */
    return (NULL);
}

/* Symantec Web Security decoder
 * Will extract the action, srcip, id, url and username.
 *
 * Examples (also online at
 * http://www.ossec.net/wiki/index.php/Symantec_WebSecurity ).
 * 20070717,73613,1=5,11=10.1.1.3,10=userc,3=1,2=1
 * 20070717,73614,1=5,11=1.2.3.4,1106=News,60=http://news.bbc.co.uk/,10=userX,1000=212.58.240.42,2=27
 */
void *SymantecWS_Decoder_Exec(Eventinfo *lf)
{
    int count = 0;
    char buf_str[OS_SIZE_1024 + 1];
    char *tmp_str = NULL;

    /* Initialize buffer */
    buf_str[0] = '\0';
    buf_str[OS_SIZE_1024] = '\0';

    /* Remove date and time */
    if (!(tmp_str = strchr(lf->log, ','))) {
        return (NULL);
    }
    if (!(tmp_str = strchr(tmp_str, ','))) {
        return (NULL);
    }
    tmp_str++;

    /* Get all the values */
    while (tmp_str != NULL) {
        /* Check if we have the username */
        if (strncmp(tmp_str, "10=", 3) == 0) {
            count = 0;
            tmp_str += 3;
            while (*tmp_str != '\0' && count < 128 && *tmp_str != ',') {
                buf_str[count] = *tmp_str;
                count++;
                tmp_str++;
            }
            buf_str[count] = '\0';

            if (!lf->dstuser) {
                os_strdup(buf_str, lf->dstuser);
            }
        }

        /* Check the IP address */
        else if (strncmp(tmp_str, "11=", 3) == 0) {
            count = 0;
            tmp_str += 3;
            while (*tmp_str != '\0' && count < 128 && *tmp_str != ',') {
                buf_str[count] = *tmp_str;
                count++;
                tmp_str++;
            }
            buf_str[count] = '\0';

            /* Avoid memory leaks -- only adding the first one */
            if (!lf->srcip) {
                os_strdup(buf_str, lf->srcip);
            }
        }

        /* Get the URL */
        else if (strncmp(tmp_str, "60=", 3) == 0) {
            count = 0;
            tmp_str += 3;
            while (*tmp_str != '\0' && count < OS_SIZE_1024 && *tmp_str != ',') {
                buf_str[count] = *tmp_str;
                count++;
                tmp_str++;
            }
            buf_str[count] = '\0';

            /* Avoid memory leaks -- only adding the first one */
            if (!lf->url) {
                os_strdup(buf_str, lf->url);
            }
        }

        /* Get ID */
        else if ((strncmp(tmp_str, "3=", 2) == 0) ||
                 (strncmp(tmp_str, "2=", 2) == 0)) {
            count = 0;
            while (*tmp_str != '\0' && count < 9) {
                buf_str[count] = *tmp_str;
                count++;
                tmp_str++;
            }
            buf_str[count] = '\0';

            /* Avoid memory leaks -- only adding the first one */
            if (!lf->id) {
                os_strdup(buf_str, lf->id);
            }
        }

        /* Get next entry */
        tmp_str = strchr(tmp_str, ',');
        if (tmp_str) {
            tmp_str++;
        }
    }

    return (NULL);
}

