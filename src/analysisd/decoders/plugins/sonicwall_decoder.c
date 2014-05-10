/* @(#) $Id: ./src/analysisd/decoders/plugins/sonicwall_decoder.c, 2011/09/08 dcid Exp $
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
#include "eventinfo.h"


/* Regex to extract the priority and event id */
#define SONICWALL_REGID  "pri=(\\d) c=(\\d+) m=(\\d+) "

/* Regex to extract the srcip and dst ip */
#define SONICWALL_REGEX "src=(\\d+.\\d+.\\d+.\\d+):(\\d+):\\S+ " \
                        "dst=(\\d+.\\d+.\\d+.\\d+):(\\d+):"

/* Regex for the web proxy messages */
#define SONICWALL_PROXY "result=(\\d+) dstname=(\\S+) arg=(\\S+)$"



/** Global variables -- not thread safe. If we ever multi thread
 * analysisd, these will need to be changed.
 */
OSRegex *__sonic_regex_prid = NULL;
OSRegex *__sonic_regex_sdip = NULL;
OSRegex *__sonic_regex_prox = NULL;



/* SonicWall decoder init */
void *SonicWall_Decoder_Init()
{
    debug1("%s: Initializing SonicWall decoder..", ARGV0);


    /* Allocating memory */
    os_calloc(1, sizeof(OSRegex), __sonic_regex_sdip);
    os_calloc(1, sizeof(OSRegex), __sonic_regex_prid);
    os_calloc(1, sizeof(OSRegex), __sonic_regex_prox);

    /* Compiling our regexes */
    if(!OSRegex_Compile(SONICWALL_REGEX, __sonic_regex_sdip, OS_RETURN_SUBSTRING))
    {
        merror(REGEX_COMPILE, ARGV0, SONICWALL_REGEX, __sonic_regex_sdip->error);
        return(0);
    }
    if(!OSRegex_Compile(SONICWALL_REGID, __sonic_regex_prid, OS_RETURN_SUBSTRING))
    {
        merror(REGEX_COMPILE, ARGV0, SONICWALL_REGID, __sonic_regex_prid->error);
        return(0);
    }
    if(!OSRegex_Compile(SONICWALL_PROXY, __sonic_regex_prox, OS_RETURN_SUBSTRING))
    {
        merror(REGEX_COMPILE, ARGV0, SONICWALL_PROXY, __sonic_regex_prox->error);
        return(0);
    }

    /* We must have the sub_strings to retrieve the nodes */
    if(!__sonic_regex_sdip->sub_strings)
    {
        merror(REGEX_SUBS, ARGV0, SONICWALL_REGEX);
        return(0);
    }
    if(!__sonic_regex_prid->sub_strings)
    {
        merror(REGEX_SUBS, ARGV0, SONICWALL_REGID);
        return(0);
    }
    if(!__sonic_regex_prox->sub_strings)
    {
        merror(REGEX_SUBS, ARGV0, SONICWALL_PROXY);
        return(0);
    }

    /* There is nothing else to do over here */
    return(NULL);
}



/* SonicWall decoder
 * Will extract the id, severity, action, srcip, dstip, protocol,srcport,dstport
 * severity will be extracted as status.
 * Examples:
 * Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time="2007-01-03 14:48:06" fw=1.1.1.1 pri=6 c=262144 m=98 msg="Connection Opened" n=23419 src=2.2.2.2:36701:WAN dst=1.1.1.1:50000:WAN proto=tcp/50000
 * Jan  3 13:45:36 192.168.5.1 id=firewall sn=000SERIAL time="2007-01-03 14:48:07" fw=1.1.1.1 pri=1 c=32 m=30 msg="Administrator login denied due to bad credentials" n=7 src=2.2.2.2:36701:WAN dst=1.1.1.1:50000:WAN
 */
void *SonicWall_Decoder_Exec(Eventinfo *lf)
{
    int i = 0;
    char category[8];
    const char *tmp_str = NULL;


    /* Zeroing category */
    category[0] = '\0';
    lf->decoder_info->type = SYSLOG;



    /** We first run our regex to extract the severity, cat and id. **/
    if(!(tmp_str = OSRegex_Execute(lf->log, __sonic_regex_prid)))
    {
        return(NULL);
    }

    /* Getting severity, id and category */
    if(__sonic_regex_prid->sub_strings[0] &&
       __sonic_regex_prid->sub_strings[1] &&
       __sonic_regex_prid->sub_strings[2])
    {
        lf->status = __sonic_regex_prid->sub_strings[0];
        lf->id = __sonic_regex_prid->sub_strings[2];


        /* Getting category */
        strncpy(category, __sonic_regex_prid->sub_strings[1], 7);


        /* Clearing all substrings */
        __sonic_regex_prid->sub_strings[0] = NULL;
        __sonic_regex_prid->sub_strings[2] = NULL;

        free(__sonic_regex_prid->sub_strings[1]);
        __sonic_regex_prid->sub_strings[1] = NULL;
    }
    else
    {
        i = 0;
        while(__sonic_regex_prid->sub_strings[i])
        {
            free(__sonic_regex_prid->sub_strings[i]);
            __sonic_regex_prid->sub_strings[i] = NULL;
            i++;
        }

        return(NULL);
    }




    /** Getting ips and ports **/
    if(!(tmp_str = OSRegex_Execute(tmp_str, __sonic_regex_sdip)))
    {
        return(NULL);
    }
    if(__sonic_regex_sdip->sub_strings[0] &&
       __sonic_regex_sdip->sub_strings[1] &&
       __sonic_regex_sdip->sub_strings[2] &&
       __sonic_regex_sdip->sub_strings[3])
    {
        /* Setting all the values */
        lf->srcip = __sonic_regex_sdip->sub_strings[0];
        lf->srcport = __sonic_regex_sdip->sub_strings[1];
        lf->dstip = __sonic_regex_sdip->sub_strings[2];
        lf->dstport = __sonic_regex_sdip->sub_strings[3];


        /* Clearing substrings */
        __sonic_regex_sdip->sub_strings[0] = NULL;
        __sonic_regex_sdip->sub_strings[1] = NULL;
        __sonic_regex_sdip->sub_strings[2] = NULL;
        __sonic_regex_sdip->sub_strings[3] = NULL;


        /* Looking for protocol */
        tmp_str = strchr(tmp_str, ' ');
        if(tmp_str)
        {
            tmp_str++;
            if(strncmp(tmp_str, "proto=", 6) == 0)
            {
                char *proto = NULL;

                i = 0;
                tmp_str += 6;


                /* Allocating memory for the protocol */
                os_calloc(8, sizeof(char), proto);
                while(isValidChar(*tmp_str) && (*tmp_str != '/'))
                {
                    proto[i] = *tmp_str;
                    i++;
                    tmp_str++;

                    if(i >= 6)
                    {
                        break;
                    }
                }

                /* Setting protocol to event info structure */
                lf->protocol = proto;
            }
        }
    }
    else
    {
        i = 0;
        while(__sonic_regex_sdip->sub_strings[i])
        {
            free(__sonic_regex_sdip->sub_strings[i]);
            __sonic_regex_sdip->sub_strings[i] = 0;
            i++;
        }

        return(NULL);
    }




    /** Setting the category/action based on the id. **/

    /* IDS event */
    if(strcmp(category, "32") == 0)
    {
        lf->decoder_info->type = IDS;
    }

    /* Firewall connection opened */
    else if((strcmp(lf->id, "98") == 0) ||
            (strcmp(lf->id, "597") == 0) ||
            (strcmp(lf->id, "598") == 0))
    {
        lf->decoder_info->type = FIREWALL;
        os_strdup("pass", lf->action);
    }

    /* Firewall connection dropped */
    else if((strcmp(lf->id, "38") == 0) ||
            (strcmp(lf->id, "36") == 0) ||
            (strcmp(lf->id, "173") == 0) ||
            (strcmp(lf->id, "174") == 0) ||
            (strcmp(lf->id, "37") == 0))
    {
        lf->decoder_info->type = FIREWALL;
        os_strdup("drop", lf->action);
    }

    /* Firewall connection closed */
    else if(strcmp(lf->id, "537") == 0)
    {
        lf->decoder_info->type = FIREWALL;
        os_strdup("close", lf->action);
    }

    /* Proxy msg */
    else if(strcmp(lf->id, "97") == 0)
    {
        lf->decoder_info->type = SQUID;


        /* Checking if tmp_str is valid */
        if(!tmp_str)
        {
            return(NULL);
        }


        /* We first run our regex to extract the severity and id. */
        if(!OSRegex_Execute(tmp_str, __sonic_regex_prox))
        {
            return(NULL);
        }


        /* Getting HTTP responde code as id */
        if(__sonic_regex_prox->sub_strings[0])
        {
            free(lf->id);
            lf->id = __sonic_regex_prox->sub_strings[0];
            __sonic_regex_prox->sub_strings[0] = NULL;
        }
        else
        {
            return(NULL);
        }


        /* Getting HTTP page */
        if(__sonic_regex_prox->sub_strings[1] &&
           __sonic_regex_prox->sub_strings[2])
        {
            char *final_url;
            int url_size = strlen(__sonic_regex_prox->sub_strings[1]) +
                           strlen(__sonic_regex_prox->sub_strings[2]) + 2;

            os_calloc(url_size +1, sizeof(char), final_url);
            snprintf(final_url, url_size, "%s%s",
                                __sonic_regex_prox->sub_strings[1],
                                __sonic_regex_prox->sub_strings[2]);


            /* Clearing the memory */
            free(__sonic_regex_prox->sub_strings[1]);
            free(__sonic_regex_prox->sub_strings[2]);
            __sonic_regex_prox->sub_strings[1] = NULL;
            __sonic_regex_prox->sub_strings[2] = NULL;


            /* Setting the url */
            lf->url = final_url;
        }
        else
        {
            merror("%s: Error getting regex - SonicWall." , ARGV0);
        }

        return(NULL);
    }


    return(NULL);
}

/* END Decoder */
