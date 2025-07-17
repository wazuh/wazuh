/*
 * Wazuh Syscheck
 * Copyright (C) 2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_OS_SPECIALIZATION_H
#define _FIMDB_OS_SPECIALIZATION_H

#include "fimDB.hpp"
#include "fimCommonDefs.h"
#include "encodingWindowsHelper.h"
#include "fimDBSpecializationWindows.hpp"

template <OSType osType>
class FIMDBCreator final
{
    public:
        static void setLimits(__attribute__((unused)) std::shared_ptr<DBSync> DBSyncHandler,
                              __attribute__((unused)) const unsigned int& fileLimit,
                              __attribute__((unused)) const unsigned int& registryLimit)
        {
            throw std::runtime_error
            {
                "Error setting limits."
            };
        }

        static std::string CreateStatement()
        {
            throw std::runtime_error
            {
                "Error creating FIMDB statement."
            };
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode)
        {
            throw std::runtime_error
            {
                "Error encoding strings."
            };
        }
};

template <>
class FIMDBCreator<OSType::WINDOWS> final
{
    public:
        static void setLimits(std::shared_ptr<DBSync> DBSyncHandler,
                              const int fileLimit,
                              const int registryLimit)
        {
            DBSyncHandler->setTableMaxRow("file_entry", fileLimit);
            DBSyncHandler->setTableMaxRow("registry_key", registryLimit);
            DBSyncHandler->setTableMaxRow("registry_data", registryLimit);

        }

        static std::string CreateStatement()
        {
            std::string ret { CREATE_FILE_DB_STATEMENT };
            ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
            ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;

            return ret;
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode)
        {
            WindowsSpecialization::encodeString(stringToEncode);
        }
};

template <>
class FIMDBCreator<OSType::OTHERS> final
{
    public:
        static void setLimits(std::shared_ptr<DBSync> DBSyncHandler,
                              const int fileLimit,
                              __attribute__((unused)) const int registryLimit)
        {
            DBSyncHandler->setTableMaxRow("file_entry", fileLimit);
        }

        static std::string CreateStatement()
        {
            return CREATE_FILE_DB_STATEMENT;
        }

        static void encodeString(__attribute__((unused)) std::string& stringToEncode){}
};

template <OSType osType>
class RegistryTypes final
{
    public:
        // LCOV_EXCL_START
        static const std::string typeText(__attribute__((unused))const int32_t type)
        {
            throw std::runtime_error { "Invalid call for this operating system"};
        };
        // LCOV_EXCL_STOP
};
template <>
class RegistryTypes<OSType::WINDOWS> final
{
    public:
        static const std::string typeText(const int32_t type)
        {
            return WindowsSpecialization::registryTypeToText(type);
        };
};

#endif // _FIMDB_OS_SPECIALIZATION_H
