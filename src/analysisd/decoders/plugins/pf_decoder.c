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


/* OpenBSD PF decoder init */
void *PF_Decoder_Init()
{
    debug1("%s: Initializing PF decoder..", ARGV0);

    /* There is nothing to do over here */
    return (NULL);
}

/* OpenBSD PF decoder
 * Will extract the action,srcip,dstip,protocol,srcport,dstport
 *
 * Examples:
 * Mar 30 15:33:26 enigma pf: Mar 30 15:32:33.483712 rule 2/(match) pass in on xl0: 140.211.166.3.6667 > 192.168.2.10.16290: P 7408:7677(269) ack 1773 win 2520 <nop,nop,timestamp 3960674784 2860123562> (DF)
 * Mar 30 15:47:05.522341 rule 4/(match) block in on lo0: 127.0.0.1.48784 > 127.0.0.1.23: S 1381529123:1381529123(0) win 16384 <mss 33184,nop,nop,sackOK,nop,wscale 0,[|tcp]> (DF) [tos 0x10]
 * Mar 30 15:54:22.171929 rule 3/(match) pass out on xl0: 192.168.2.10.1514 > 192.168.2.190.1030:  udp 73
 * Mar 30 15:54:22.174412 rule 3/(match) pass out on xl0: 192.168.2.10.1514 > 192.168.2.190.1030:  udp 89
 * Mar 30 17:47:40.390143 rule 2/(match) pass in on lo0: 127.0.0.1 > 127.0.0.1: icmp: echo reply
 * Mar 30 17:47:41.400075 rule 3/(match) pass out on lo0: 127.0.0.1 > 127.0.0.1: icmp: echo request
 */
void *PF_Decoder_Exec(Eventinfo *lf)
{
    int port_count = 0;
    char *tmp_str;
    char *aux_str;

    /* tmp_str should be: Mar 30 15:54:22.171929 rule 3/(match) pass out .. */
    tmp_str = strchr(lf->log, ')');

    /* Didn't match */
    if (!tmp_str) {
        return (NULL);
    }

    /* Go to the action entry */
    tmp_str++;
    if (*tmp_str != ' ') {
        return (NULL);
    }
    tmp_str++;

    /* tmp_str should be: pass out on xl0: 192.168.2.10.1514 .. */

    /* Get action */
    if (*tmp_str == 'p') {
        os_strdup("pass", lf->action);
    } else if (*tmp_str == 'b') {
        os_strdup("block", lf->action);
    } else {
        /* Unknown action */
        return (NULL);
    }

    /* Jump to the src ip */
    tmp_str = strchr(tmp_str, ':');
    if (!tmp_str) {
        return (NULL);
    }
    tmp_str++;
    if (*tmp_str != ' ') {
        return (NULL);
    }
    tmp_str++;

    /* tmp_str should be: 192.168.2.10.1514 > .. */
    aux_str = strchr(tmp_str, ' ');
    if (!aux_str) {
        return (NULL);
    }

    /* Set aux_str to 0 for strdup */
    *aux_str = '\0';

    os_strdup(tmp_str, lf->srcip);

    /* Aux str has a valid pointer to lf->log now */
    *aux_str = ' ';
    aux_str++;

    /* Set the source port if present */
    tmp_str = lf->srcip;
    while (*tmp_str != '\0') {
        if (*tmp_str == '.') {
            port_count++;
        }

        /* Found port */
        if (port_count == 4) {
            *tmp_str = '\0';
            tmp_str++;
            os_strdup(tmp_str, lf->srcport);
            break;
        }

        tmp_str++;
    }

    /* Invalid rest of log */
    if (*aux_str != '>') {
        return (NULL);
    }

    aux_str++;
    if (*aux_str != ' ') {
        return (NULL);
    }
    aux_str++;

    /* tmp_str should be: 192.168.2.10.1514: .. .. */
    tmp_str = strchr(aux_str, ':');
    if (!tmp_str) {
        return (NULL);
    }

    /* Set aux_str to 0 for strdup */
    *tmp_str = '\0';

    os_strdup(aux_str, lf->dstip);

    /* tmp str has a valid pointer to lf->log now */
    *tmp_str = ':';
    tmp_str++;

    /* Get destination port */
    aux_str = lf->dstip;
    port_count = 0;
    while (*aux_str != '\0') {
        if (*aux_str == '.') {
            port_count++;
        }

        /* Found port */
        if (port_count == 4) {
            *aux_str = '\0';
            aux_str++;
            os_strdup(aux_str, lf->dstport);
            break;
        }

        aux_str++;
    }

    /* Get protocol */
    while (*tmp_str != '\0') {
        if (*tmp_str == ' ') {
            tmp_str++;
            continue;
        } else if (*tmp_str == 'u') {
            os_strdup("UDP", lf->protocol);
        } else if (*tmp_str == 'i') {
            os_strdup("ICMP", lf->protocol);
        } else {
            os_strdup("TCP", lf->protocol);
        }

        break;
    }

    return (NULL);
}

