/* @(#) $Id: ./src/rootcheck/check_rc_if.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WIN32
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Solaris happy again */
#ifdef SOLARIS
#include <stropts.h>
#include <sys/sockio.h>
#endif

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"

#ifndef IFCONFIG
#define IFCONFIG "ifconfig %s | grep PROMISC > /dev/null 2>&1"
#endif

static int run_ifconfig(const char *ifconfig);

/* run_ifconfig: Execute the ifconfig command.
 * Returns 1 if interface in promisc mode.
 */
static int run_ifconfig(const char *ifconfig)
{
    char nt[OS_SIZE_1024 +1];

    snprintf(nt, OS_SIZE_1024, IFCONFIG, ifconfig);

    if(system(nt) == 0)
        return(1);

    return(0);
}


/*  check_rc_if: v0.1
 *  Check all interfaces for promiscuous mode
 */
void check_rc_if()
{
    int _fd, _errors = 0, _total = 0;
    struct ifreq tmp_str[16];

    struct ifconf _if;
    struct ifreq *_ir;
    struct ifreq *_ifend;
    struct ifreq _ifr;

    _fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(_fd < 0)
    {
        merror("%s: Error checking interfaces (socket)", ARGV0);
        return;
    }


    memset(tmp_str, 0, sizeof(struct ifreq)*16);
    _if.ifc_len = sizeof(tmp_str);
    _if.ifc_buf = (caddr_t)(tmp_str);

    if (ioctl(_fd, SIOCGIFCONF, &_if) < 0)
    {
        close(_fd);
        merror("%s: Error checking interfaces (ioctl)", ARGV0);
        return;
    }

    _ifend = (struct ifreq*) (void *) ((char*)tmp_str + _if.ifc_len);
    _ir = tmp_str;

    /* Looping on all interfaces */
    for (; _ir < _ifend; _ir++)
    {
        strncpy(_ifr.ifr_name, _ir->ifr_name, sizeof(_ifr.ifr_name));

        /* Getting information from each interface */
        if (ioctl(_fd, SIOCGIFFLAGS, (char*)&_ifr) == -1)
        {
            continue;
        }

        _total++;


        if ((_ifr.ifr_flags & IFF_PROMISC) )
        {
            char op_msg[OS_SIZE_1024 +1];
            if(run_ifconfig(_ifr.ifr_name))
            {
                snprintf(op_msg, OS_SIZE_1024,"Interface '%s' in promiscuous"
                                            " mode.", _ifr.ifr_name);
                notify_rk(ALERT_SYSTEM_CRIT, op_msg);
            }
            else
            {
                snprintf(op_msg, OS_SIZE_1024,"Interface '%s' in promiscuous"
                                 " mode, but ifconfig is not showing it"
                                 "(probably trojaned).", _ifr.ifr_name);
                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
            _errors++;
        }
    }
    close(_fd);

    if(_errors == 0)
    {
        char op_msg[OS_SIZE_1024 +1];
        snprintf(op_msg, OS_SIZE_1024, "No problem detected on ifconfig/ifs."
                                    " Analyzed %d interfaces.", _total);
        notify_rk(ALERT_OK, op_msg);
    }

    return;
}

/* EOF */

#else
void check_rc_if()
{
    return;
}
#endif
