/*   $OSSEC, check_rc_if.c, v0.1, 2005/10/07, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <sys/ioctl.h>       
#include <net/if.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
 

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"

#ifndef IFCONFIG
#define IFCONFIG "ifconfig %s | grep PROMISC > /dev/null 2>&1"
#endif


/* run_ifconfig: Execute the ifconfig command.
 * Returns 1 if interface in promisc mode.
 */
int run_ifconfig(char *ifconfig)
{
    char nt[OS_MAXSTR +1];

    snprintf(nt, OS_MAXSTR, IFCONFIG, ifconfig);

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
                                     
    _ifend = (struct ifreq*) ((char*)tmp_str + _if.ifc_len);
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
            char op_msg[OS_MAXSTR +1];
            if(run_ifconfig(_ifr.ifr_name))
            {
                snprintf(op_msg, OS_MAXSTR, "Interface '%s' in promiscuous"
                                            " mode.", _ifr.ifr_name);
                notify_rk(ALERT_SYSTEM_CRIT, op_msg);
            }
            else
            {
                snprintf(op_msg, OS_MAXSTR, "Interface '%s' in promiscuous"
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
        char op_msg[OS_MAXSTR +1];
        snprintf(op_msg, OS_MAXSTR, "No problem detected on ifconfig/ifs."
                                    " Analized %d interfaces.", _total);
        notify_rk(ALERT_OK, op_msg);
    }
    
    return;
}

/* EOF */
