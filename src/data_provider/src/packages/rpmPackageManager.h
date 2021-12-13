#ifndef RPM_PACKAGE_MANAGER_H
#define RPM_PACKAGE_MANAGER_H

#include <string>
#include <vector>
#include <memory>

#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>

#include "rpmlibWrapper.h"

// Provides an iterable abstraction for retrieving installed RPM packages.
class RpmPackageManager final
{
public:
    RpmPackageManager(std::unique_ptr<IRpmLibWrapper> &&wrapper);
    ~RpmPackageManager();
    struct Package
    {
        std::string name;
        std::string version;
        std::string release;
        std::string epoch;
        std::string summary;
        std::string installTime;
        uint64_t size;
        std::string vendor;
        std::string group;
        std::string source;
        std::string architecture;
        std::string description;
    };

    struct Iterator final {
        bool operator!=(const Iterator &other)
        {
            return m_end != other.m_end;
        };
        void operator++();
        Package operator*();
        ~Iterator();
    private:
        Iterator(bool end = false);
        std::string getAttribute(rpmTag tag);
        uint64_t getAttributeNumber(rpmTag tag);
        bool m_end = false;
        rpmts m_transactionSet = nullptr;
        rpmdbMatchIterator m_matches = nullptr;
        rpmtd m_dataContainer = nullptr;
        Header m_header = nullptr;
        friend class RpmPackageManager;
    };
    static const Iterator END_ITERATOR;
    Iterator begin()
    {
        return Iterator{};
    }
    const Iterator &end()
    {
        return END_ITERATOR;
    }
private:
    std::unique_ptr<IRpmLibWrapper> rpmlib;
};

#endif // RPM_PACKAGE_MANAGER_H
