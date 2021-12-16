#include "rpmPackageManager.h"

#include <exception>
#include <map>
#include <stdexcept>
#include <vector>
#include <iostream>

// For O_RDONLY
#include <fcntl.h>

bool instantiated = false;

RpmPackageManager::RpmPackageManager(std::shared_ptr<IRpmLibWrapper> &&wrapper)
: m_rpmlib{wrapper}
{
    if (instantiated) {
        throw std::runtime_error("there is another RPM instance already created");
    }
    if (m_rpmlib->rpmReadConfigFiles(nullptr, nullptr))
    {
        throw std::runtime_error("rpmReadConfigFiles failed");
    }
    instantiated = true;
}

RpmPackageManager::~RpmPackageManager() {
    m_rpmlib->rpmFreeRpmrc();
    instantiated = false;
}

std::string RpmPackageManager::Iterator::getAttribute(rpmTag tag)
{
    if (m_rpmlib->headerGet(m_header, tag, m_dataContainer, HEADERGET_DEFAULT) == 0)
    {
        return "";
    }
    auto cstr = m_rpmlib->rpmtdGetString(m_dataContainer);
    if (!cstr)
    {
        return "";
    }
    return cstr;
}

uint64_t RpmPackageManager::Iterator::getAttributeNumber(rpmTag tag)
{
    if (m_rpmlib->headerGet(m_header, tag, m_dataContainer, HEADERGET_DEFAULT) == 0)
    {
        return 0;
    }
    return m_rpmlib->rpmtdGetNumber(m_dataContainer);
}

const RpmPackageManager::Iterator RpmPackageManager::END_ITERATOR{};

RpmPackageManager::Iterator::Iterator()
: m_end{true}
{

}

RpmPackageManager::Iterator::Iterator(std::shared_ptr<IRpmLibWrapper> &rpmlib)
: m_end{false},
  m_rpmlib{rpmlib}
{
    m_transactionSet = rpmlib->rpmtsCreate();
    if (!m_transactionSet)
    {
        throw std::runtime_error("rpmtsCreate failed");
    }
    if (rpmlib->rpmtsOpenDB(m_transactionSet, O_RDONLY))
    {
        throw std::runtime_error("rpmtsOpenDB failed");
    }
    if (rpmlib->rpmtsRun(m_transactionSet, nullptr, 0))
    {
        throw std::runtime_error("rpmtsRun failed");
    }
    m_dataContainer = rpmlib->rpmtdNew();
    if (!m_dataContainer)
    {
        throw std::runtime_error("rpmtdNew failed");
    }
    m_matches = rpmlib->rpmtsInitIterator(m_transactionSet, RPMTAG_NAME, nullptr, 0);
    if (!m_matches)
    {
        throw std::runtime_error("rpmtsInitIterator failed");
    }
    // Prepare for first call to dereference (*) operator.
    ++(*this);
}

RpmPackageManager::Iterator::~Iterator()
{
    if (m_transactionSet)
    {
        m_rpmlib->rpmtsCloseDB(m_transactionSet);
        m_rpmlib->rpmtsFree(m_transactionSet);
    }
    if (m_dataContainer)
    {
        m_rpmlib->rpmtdFree(m_dataContainer);
    }
    if (m_matches)
    {
        m_rpmlib->rpmdbFreeIterator(m_matches);
    }
}

void RpmPackageManager::Iterator::operator++()
{
    m_header = m_rpmlib->rpmdbNextIterator(m_matches);
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
    p.epoch = getAttribute(RPMTAG_EPOCH);
    p.summary = getAttribute(RPMTAG_SUMMARY);
    p.installTime = getAttributeNumber(RPMTAG_INSTALLTIME);
    p.size = getAttributeNumber(RPMTAG_SIZE);
    p.vendor = getAttribute(RPMTAG_VENDOR);
    p.group = getAttribute(RPMTAG_GROUP);
    p.source = getAttribute(RPMTAG_SOURCE);
    p.architecture = getAttribute(RPMTAG_ARCH);
    p.description = getAttribute(RPMTAG_DESCRIPTION);
    return p;
}
