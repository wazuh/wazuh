/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * March 17, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stropts.h>
#include <unistd.h>
#include <fcntl.h>

#include <memory>

#include "portSolarisHelper.hpp"

int PortSolarisHelper::tcpConnEntrySize;
int PortSolarisHelper::tcp6ConnEntrySize;
int PortSolarisHelper::udpEntrySize;
int PortSolarisHelper::udp6EntrySize;

// this code was extracted and adapted of OpenSolaris netstate tool implementation
void PortSolarisHelper::mibGetItems(int sd, std::deque<mibItem>& items)
{
    uintptr_t   buf[512 / sizeof (uintptr_t)];
    int flags;
    int getcode;
    struct strbuf ctlbuf;
    struct T_optmgmt_req*    tor = (struct T_optmgmt_req*)buf;
    struct T_optmgmt_ack*    toa = (struct T_optmgmt_ack*)buf;
    struct T_error_ack*  tea = (struct T_error_ack*)buf;
    struct opthdr*       req;

    tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
    tor->OPT_offset = sizeof (struct T_optmgmt_req);
    tor->OPT_length = sizeof (struct opthdr);
    tor->MGMT_flags = T_CURRENT;

    /*
     * Note: we use the special level value below so that IP will return
     * us information concerning IRE_MARK_TESTHIDDEN routes.
     */
    req = (struct opthdr*)&tor[1];
    req->level = EXPER_IP_AND_ALL_IRES;
    req->name  = 0;
    req->len   = 0;

    ctlbuf.buf = (char*)buf;
    ctlbuf.len = tor->OPT_length + tor->OPT_offset;
    flags = 0;

    if (putmsg(sd, &ctlbuf, (struct strbuf*)0, flags) == -1)
    {
        return;
    }

    /*
     * Each reply consists of a ctl part for one fixed structure
     * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
     * containing an opthdr structure.  level/name identify the entry,
     * len is the size of the data part of the message.
     */
    req = (struct opthdr*)&toa[1];
    ctlbuf.maxlen = sizeof (buf);

    while (1)
    {
        flags = 0;
        getcode = getmsg(sd, &ctlbuf, (struct strbuf*)0, &flags);

        if (getcode == -1)
        {
            break;
        }

        if (getcode == 0 && ctlbuf.len >= sizeof (struct T_optmgmt_ack) &&
                toa->PRIM_type == T_OPTMGMT_ACK && toa->MGMT_flags == T_SUCCESS &&
                req->len == 0)
        {
            break;     /* this is EOD msg */
        }

        if (ctlbuf.len >= sizeof (struct T_error_ack) && tea->PRIM_type == T_ERROR_ACK)
        {
            break;
        }

        if (getcode != MOREDATA || ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
                toa->PRIM_type != T_OPTMGMT_ACK || toa->MGMT_flags != T_SUCCESS)
        {
            break;
        }

        mibItem item
        {
            req->level,
            req->name,
            req->len,
            std::shared_ptr<char>(new char[req->len])
        };

        struct strbuf databuf
        {
            item.length,
            0,
            item.val.get()
        };

        flags = 0;
        getcode = getmsg(sd, (struct strbuf*)0, &databuf, &flags);

        if (getcode != 0)
        {
            break;
        }

        items.push_back(item);
    }

    return;
}

// this code was extracted and adapted of OpenSolaris netstate tool implementation
int PortSolarisHelper::mibOpen(void)
{
    int sd;

    sd = open("/dev/arp", O_RDWR);

    if (sd == -1)
    {
        perror("arp open");
        return (-1);
    }

    if (ioctl(sd, I_PUSH, "tcp") == -1)
    {
        perror("tcp I_PUSH");
        (void) close(sd);
        return (-1);
    }

    if (ioctl(sd, I_PUSH, "udp") == -1)
    {
        perror("udp I_PUSH");
        (void) close(sd);
        return (-1);
    }

    return (sd);
}

// this code was extracted and adapted of OpenSolaris netstate tool implementation
void PortSolarisHelper::mibGetConstants(std::deque<mibItem>& items)
{
    for (auto& item : items)
    {
        if (item.mib_id != 0)
            continue;

        switch (item.group)
        {
            case MIB2_TCP:
                {
                    mib2_tcp_t*  tcp = (mib2_tcp_t*)item.val.get();

                    tcpConnEntrySize = tcp->tcpConnTableSize;
                    tcp6ConnEntrySize = tcp->tcp6ConnTableSize;
                    break;
                }

            case MIB2_UDP:
                {
                    mib2_udp_t*  udp = (mib2_udp_t*)item.val.get();
                    udpEntrySize = udp->udpEntrySize;
                    udp6EntrySize = udp->udp6EntrySize;
                    break;
                }
        }
    }
}
