/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "rpmPackageManager.h"

#include <exception>
#include <map>
#include <stdexcept>
#include <vector>
#include <iostream>

// For O_RDONLY
#include <fcntl.h>

bool RpmPackageManager::ms_instantiated = false;

RpmPackageManager::RpmPackageManager(std::shared_ptr<IRpmLibWrapper>&& wrapper)
    : m_rpmlib{wrapper}
{
    if (ms_instantiated)
    {
        throw std::runtime_error("there is another RPM instance already created");
    }

    if (m_rpmlib->rpmReadConfigFiles(nullptr, nullptr))
    {
        throw std::runtime_error("rpmReadConfigFiles failed");
    }

    ms_instantiated = true;
}

RpmPackageManager::~RpmPackageManager()
{
    m_rpmlib->rpmFreeRpmrc();
    ms_instantiated = false;
}

std::string RpmPackageManager::Iterator::getAttribute(rpmTag tag) const
{
    std::string retval;

    if (m_rpmlib->headerGet(m_header, tag, m_dataContainer.get(), HEADERGET_DEFAULT))
    {
        auto cstr {m_rpmlib->rpmtdGetString(m_dataContainer.get())};

        if (cstr)
        {
            retval = cstr;
        }
    }

    return retval;
}

uint64_t RpmPackageManager::Iterator::getAttributeNumber(rpmTag tag) const
{
    uint64_t retval {};

    if (m_rpmlib->headerGet(m_header, tag, m_dataContainer.get(), HEADERGET_DEFAULT))
    {
        retval = m_rpmlib->rpmtdGetNumber(m_dataContainer.get());
    }

    return retval;
}

const RpmPackageManager::Iterator RpmPackageManager::END_ITERATOR{};

RpmPackageManager::Iterator::Iterator()
    : m_end{true}
{

}

RpmPackageManager::Iterator::Iterator(std::shared_ptr<IRpmLibWrapper>& rpmlib)
    : m_end{false},
      m_rpmlib{rpmlib},
      m_transactionSet{rpmlib->rpmtsCreate(), rpmtsFree}
{
    if (!m_transactionSet)
    {
        throw std::runtime_error("rpmtsCreate failed");
    }

    if (rpmlib->rpmtsOpenDB(m_transactionSet.get(), O_RDONLY))
    {
        throw std::runtime_error("rpmtsOpenDB failed");
    }

    if (rpmlib->rpmtsRun(m_transactionSet.get(), nullptr, 0))
    {
        throw std::runtime_error("rpmtsRun failed");
    }

    m_dataContainer = TagDataContainer{rpmlib->rpmtdNew(), rpmtdFree};

    if (!m_dataContainer)
    {
        throw std::runtime_error("rpmtdNew failed");
    }

    m_matches = RpmIterator(rpmlib->rpmtsInitIterator(m_transactionSet.get(), RPMTAG_NAME, nullptr, 0), rpmdbFreeIterator);

    if (!m_matches)
    {
        throw std::runtime_error("rpmtsInitIterator failed");
    }

    // Prepare for first call to dereference (*) operator.
    ++(*this);
}

RpmPackageManager::Iterator::~Iterator()
{
    ms_instantiated = false;
}

void RpmPackageManager::Iterator::operator++()
{
    m_header = m_rpmlib->rpmdbNextIterator(m_matches.get());

    if (!m_header)
    {
        m_end = true;
    }
}

RpmPackageManager::Package RpmPackageManager::Iterator::operator*()
{
    Package p;
    p.name = getAttribute(RPMTAG_NAME);
    p.version = getAttribute(RPMTAG_VERSION);
    p.release = getAttribute(RPMTAG_RELEASE);
    p.epoch = getAttributeNumber(RPMTAG_EPOCH);
    p.summary = getAttribute(RPMTAG_SUMMARY);
    p.installTime = std::to_string(getAttributeNumber(RPMTAG_INSTALLTIME));
    p.size = getAttributeNumber(RPMTAG_SIZE);
    p.vendor = getAttribute(RPMTAG_VENDOR);
    p.group = getAttribute(RPMTAG_GROUP);
    p.source = getAttribute(RPMTAG_SOURCE);
    p.architecture = getAttribute(RPMTAG_ARCH);
    p.description = getAttribute(RPMTAG_DESCRIPTION);
    return p;
}
