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

#include "processInterfaceSolaris.h"

std::shared_ptr<IOSProcess> FactorySolarisProcess::create(const std::shared_ptr<IProcessInterfaceWrapper>& interfaceWrapper)
{
    std::shared_ptr<IOSProcess> ret;

    if (interfaceWrapper)
    {
        ret = std::make_shared<SolarisProcessImpl>(interfaceWrapper);
    }
    else
    {
        throw std::runtime_error{"Error nullptr process interfaceWrapper instance."};
    }

    return ret;
}

void SolarisProcessImpl::buildProcessData(nlohmann::json& process)
{
    process["pid"] = m_processWrapper->pid();
    process["name"] = m_processWrapper->name();
    process["state"] = m_processWrapper->state();
    process["ppid"] = m_processWrapper->ppid();
    process["utime"] = m_processWrapper->utime();
    process["stime"] = m_processWrapper->stime();
    process["cmd"] = m_processWrapper->cmd();
    process["argvs"] = m_processWrapper->argvs();
    process["euser"] = m_processWrapper->euser();
    process["ruser"] = m_processWrapper->ruser();
    process["suser"] = m_processWrapper->suser();
    process["egroup"] = m_processWrapper->egroup();
    process["rgroup"] = m_processWrapper->rgroup();
    process["sgroup"] = m_processWrapper->sgroup();
    process["fgroup"] = m_processWrapper->fgroup();
    process["priority"] = m_processWrapper->priority();
    process["nice"] = m_processWrapper->nice();
    process["size"] = m_processWrapper->size();
    process["vm_size"] = m_processWrapper->vm_size();
    process["resident"] = m_processWrapper->resident();
    process["share"] = m_processWrapper->share();
    process["start_time"] = m_processWrapper->startTime();
    process["pgrp"] = m_processWrapper->pgrp();
    process["session"] = m_processWrapper->session();
    process["nlwp"] = m_processWrapper->nlwp();
    process["tgid"] = m_processWrapper->tgid();
    process["tty"] = m_processWrapper->tty();
    process["processor"] = m_processWrapper->processor();
}
