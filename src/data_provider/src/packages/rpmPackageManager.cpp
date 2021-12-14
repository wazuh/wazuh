#include "rpmPackageManager.h"

#include <exception>
#include <map>
#include <stdexcept>
#include <vector>

// For O_RDONLY
#include <fcntl.h>

static bool instantiated = false;

RpmPackageManager::RpmPackageManager(std::unique_ptr<IRpmLibWrapper> &&wrapper)
: rpmlib{std::move(wrapper)}
{
    if (instantiated) {
        throw std::runtime_error("there is another RPM instance already created");
    }
    rpmReadConfigFiles(nullptr, nullptr);
    instantiated = true;
}

RpmPackageManager::~RpmPackageManager() {
    rpmFreeRpmrc();
    instantiated = false;
}

std::string RpmPackageManager::Iterator::getAttribute(rpmTag tag)
{
    if (headerGet(m_header, tag, m_dataContainer, HEADERGET_DEFAULT) == 0)
    {
        return "";
    }
    auto cstr = rpmtdGetString(m_dataContainer);
    if (!cstr)
    {
        return "";
    }
    return cstr;
}

uint64_t RpmPackageManager::Iterator::getAttributeNumber(rpmTag tag)
{
    if (headerGet(m_header, tag, m_dataContainer, HEADERGET_DEFAULT) == 0)
    {
        return 0;
    }
    return rpmtdGetNumber(m_dataContainer);
}

const RpmPackageManager::Iterator RpmPackageManager::END_ITERATOR{true};

RpmPackageManager::Iterator::Iterator(bool end)
: m_end{end}
{
    if (end) {
        return;
    }
    m_transactionSet = rpmtsCreate();
    if (nullptr == m_transactionSet)
    {
        throw std::runtime_error("rpmtsCreate failed");
    }
    if (rpmtsOpenDB(m_transactionSet, O_RDONLY))
    {
        throw std::runtime_error("rpmtsOpenDB failed");
    }
    if (rpmtsRun(m_transactionSet, NULL, 0))
    {
        throw std::runtime_error("rpmtsRun failed");
    }
    m_dataContainer = rpmtdNew();
    if (nullptr == m_dataContainer)
    {
        throw std::runtime_error("rpmtdNew failed");
    }
    m_matches = rpmtsInitIterator(m_transactionSet, RPMTAG_NAME, nullptr, 0);
    // Prepare for first call to dereference (*) operator.
    ++(*this);
}

RpmPackageManager::Iterator::~Iterator()
{
    if (m_transactionSet)
    {
        rpmtsCloseDB(m_transactionSet);
        rpmtsFree(m_transactionSet);
    }
    if (m_dataContainer)
    {
        rpmtdFree(m_dataContainer);
    }
    if (m_matches)
    {
        rpmdbFreeIterator(m_matches);
    }
}

void RpmPackageManager::Iterator::operator++()
{
    m_header = rpmdbNextIterator(m_matches);
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
