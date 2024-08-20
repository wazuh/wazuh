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

#ifndef _PROCESS_SOLARIS_WRAPPER_H
#define _PROCESS_SOLARIS_WRAPPER_H

#include <iosfwd>
#include <map>

// due to avoid procfs building errors in Solaris with GCC 9.4
#define _STRUCTURED_PROC 1
#include <procfs.h>

#include <limits.h>
#include <grp.h>
#include <pwd.h>

#include "iprocessWrapper.h"

const auto KBYTES_PER_PAGE{sysconf(_SC_PAGESIZE) / 1024};

class ProcessSolarisWrapper final : public IProcessInterfaceWrapper
{
    psinfo_t m_info;
    pstatus_t m_status;
    prcred_t m_cred;

public:
    explicit ProcessSolarisWrapper(const psinfo_t& psinfo, const pstatus_t status, const prcred_t cred)
        : m_info(psinfo), m_status(status), m_cred(cred)
    {
    }

    std::string pid() const override
    {
        return std::to_string(m_info.pr_pid);
    }

    std::string name() const override
    {
        return std::string(m_info.pr_fname);
    }

    std::string state() const override
    {
        return std::string(1, m_info.pr_lwp.pr_sname);
    }

    int ppid() const override
    {
        return m_info.pr_ppid;
    }

    unsigned long long utime() const override
    {
        return m_status.pr_utime.tv_sec;
    }

    unsigned long long stime() const override
    {
        return m_status.pr_stime.tv_sec;
    }

    std::string cmd() const override
    {
        std::string retVal(m_info.pr_psargs);
        const auto spacePos = retVal.find(' ');

        if (spacePos != std::string::npos)
        {
            retVal = retVal.substr(0, spacePos);
        }
        return retVal;
    }

    std::string argvs() const override
    {
        std::string retVal;
        std::string argsString(m_info.pr_psargs);
        const auto spacePos = argsString.find(' ');
        if (spacePos != std::string::npos)
        {
            retVal = argsString.substr(spacePos + 1);
        }
        return retVal;
    }

    std::string euser() const override
    {
        return getpwuid(m_cred.pr_euid)->pw_name;
    }

    std::string ruser() const override
    {
        return getpwuid(m_cred.pr_ruid)->pw_name;
    }

    std::string suser() const override
    {
        return getpwuid(m_cred.pr_suid)->pw_name;
    }

    std::string egroup() const override
    {
        return getgrgid(m_cred.pr_egid)->gr_name;
    }

    std::string rgroup() const override
    {
        return getgrgid(m_cred.pr_rgid)->gr_name;
    }

    std::string sgroup() const override
    {
        return getgrgid(m_cred.pr_sgid)->gr_name;
    }

    std::string fgroup() const override
    {
        // same of sgroup()
        return getgrgid(m_cred.pr_sgid)->gr_name;
    }

    long priority() const override
    {
        // if I'm zombie, not priority (-1)
        return (m_info.pr_lwp.pr_sname != 'Z') ? m_info.pr_lwp.pr_pri : -1L;
    }

    long nice() const override
    {
        return (m_info.pr_lwp.pr_sname != 'Z' && m_info.pr_lwp.pr_oldpri != 0) ? m_info.pr_lwp.pr_nice : -1L;
    }

    long size() const override
    {
        // size in pages
        return m_info.pr_size / KBYTES_PER_PAGE;
    }

    unsigned long vm_size() const override
    {
        return m_info.pr_size;
    }

    long resident() const override
    {
        // size in pages
        return m_info.pr_rssize / KBYTES_PER_PAGE;
    }

    long share() const override
    {
        return -1L; // discarded information is not easily obtained
    }

    unsigned long long startTime() const override
    {
        return m_info.pr_lwp.pr_start.tv_sec;
    }

    int pgrp() const override
    {
        return m_info.pr_pgid;
    }

    int session() const override
    {
        return m_info.pr_sid;
    }

    int nlwp() const override
    {
        return m_info.pr_nlwp + m_info.pr_nzomb;
    }

    int tgid() const override
    {
        return m_info.pr_taskid;
    }

    int tty() const override
    {
        return m_info.pr_ttydev == PRNODEV ? 0 : m_info.pr_ttydev;
    }

    int processor() const override
    {
        return m_info.pr_lwp.pr_cpu;
    }
};

#endif // _PROCESS_SOLARIS_WRAPPER_H
