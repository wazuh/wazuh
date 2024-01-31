/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_INTERFACE_WRAPPER_H
#define _PROCESS_INTERFACE_WRAPPER_H
#include "iprocessInterface.h"

class IProcessInterfaceWrapper
{
    public:
        // LCOV_EXCL_START
        virtual ~IProcessInterfaceWrapper() = default;
        // LCOV_EXCL_STOP
        virtual std::string pid() const = 0;
        virtual std::string name() const = 0;
        virtual std::string state() const = 0;
        virtual int ppid() const = 0;
        virtual unsigned long long utime() const = 0;
        virtual unsigned long long stime() const = 0;
        virtual std::string cmd() const = 0;
        virtual std::string argvs() const = 0;
        virtual std::string euser() const = 0;
        virtual std::string ruser() const = 0;
        virtual std::string suser() const = 0;
        virtual std::string egroup() const = 0;
        virtual std::string rgroup() const = 0;
        virtual std::string sgroup() const = 0;
        virtual std::string fgroup() const = 0;
        virtual long priority() const = 0;
        virtual long nice() const = 0;
        virtual long size() const = 0;
        virtual unsigned long vm_size() const = 0;
        virtual long resident() const = 0;
        virtual long share() const = 0;
        virtual unsigned long long startTime() const = 0;
        virtual int pgrp() const = 0;
        virtual int session() const = 0;
        virtual int nlwp() const = 0;
        virtual int tgid() const = 0;
        virtual int tty() const = 0;
        virtual int processor() const = 0;
};
#endif // _PROCESS_INTERFACE_WRAPPER_H
