/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
 
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
        RpmPackageManager(std::shared_ptr<IRpmLibWrapper>&& wrapper);
        // LCOV_EXCL_START
        ~RpmPackageManager();
        // LCOV_EXCL_STOP
        struct Package
        {
            std::string name;
            std::string version;
            std::string release;
            uint64_t epoch;
            std::string summary;
            std::string installTime;
            uint64_t size;
            std::string vendor;
            std::string group;
            std::string source;
            std::string architecture;
            std::string description;
        };

        struct Iterator final
        {
                bool operator!=(const Iterator& other)
                {
                    return m_end != other.m_end;
                };
                void operator++();
                Package operator*();
                ~Iterator();
            private:
                // Used for end iterator
                Iterator();
                // Used for regular iterator
                Iterator(std::shared_ptr<IRpmLibWrapper>& rpmlib);
                std::string getAttribute(rpmTag tag);
                uint64_t getAttributeNumber(rpmTag tag);
                bool m_end = false;
                std::shared_ptr<IRpmLibWrapper> m_rpmlib;
                rpmts m_transactionSet = nullptr;
                rpmdbMatchIterator m_matches = nullptr;
                rpmtd m_dataContainer = nullptr;
                Header m_header = nullptr;
                friend class RpmPackageManager;
        };
        static const Iterator END_ITERATOR;
        Iterator begin()
        {
            return Iterator{m_rpmlib};
        }
        const Iterator& end()
        {
            return END_ITERATOR;
        }
    private:
        std::shared_ptr<IRpmLibWrapper> m_rpmlib;
};

#endif // RPM_PACKAGE_MANAGER_H
