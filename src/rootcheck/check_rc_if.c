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
#include <string.h>
 

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"


/*  check_rc_if: v0.1
 *  Check all interfaces for promiscuous mode
 */
void check_rc_if()
{
    int _fd, i;
    char tmp_str[2* OS_MAXSTR + 1];
    
    struct ifconf _if;
    struct ifreq *_ir;
    struct ifreq _ifr;

    _fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(_fd < 0)
    {
        merror("%s: Error checking interfaces (socket)", ARGV0);
        return;
    }

 
    memset(tmp_str, '\0', 2* OS_MAXSTR +1);
    
    _if.ifc_len = sizeof(tmp_str);
    _if.ifc_buf = tmp_str;
    
    if (ioctl(_fd, SIOCGIFCONF, &_if) < 0)
    {
        merror("%s: Error checking interfaces (ioctl)", ARGV0);
        return;
    }
                                     
    _ir = _if.ifc_req;

    /* Looping on all interfaces */
    for (i = _if.ifc_len /sizeof(struct ifreq); i > 0; i--, _ir++)
    {
        strncpy(_ifr.ifr_name, _ir->ifr_name, sizeof(_ifr.ifr_name));

        /* Getting information from each interface */
        if (ioctl(_fd, SIOCGIFFLAGS, (char*)&_ifr) == -1) 
        {
            continue;
        }

        printf("name: %s\n",_ifr.ifr_name);

        if ((_ifr.ifr_flags & IFF_PROMISC) )
        {
            printf("promisc!\n");
        }
    }                                                                              

    return;
}

/* EOF */
