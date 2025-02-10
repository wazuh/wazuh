/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * February 9, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCK_SYSTEM_CONTEXT_HPP
#define _MOCK_SYSTEM_CONTEXT_HPP

#include <gmock/gmock.h>
#include <gtest/gtest.h>

// #include "json.hpp"

/**
 * @brief Mock GlobalData class.
 *
 */
class MockSystemContext
{
public:
    MockSystemContext() = default;

    virtual ~MockSystemContext() = default;

    enum class OriginTable : std::uint8_t
    {
        Packages,
        Processes,
        Os,
        Hw,
        Invalid
    };

    MOCK_METHOD(OriginTable, originTable, (), (const));
    MOCK_METHOD(std::string_view, agentId, (), (const));
    MOCK_METHOD(std::string_view, packageItemId, (), (const));
    MOCK_METHOD(std::string_view, processId, (), (const));
    MOCK_METHOD(std::string_view, agentName, (), (const));
    MOCK_METHOD(std::string_view, agentVersion, (), (const));
    MOCK_METHOD(std::string_view, agentIp, (), (const));
    MOCK_METHOD(std::string_view, osVersion, (), (const));
    MOCK_METHOD(std::string_view, osName, (), (const));
    MOCK_METHOD(std::string_view, osKernelRelease, (), (const));
    MOCK_METHOD(std::string_view, osKernelSysName, (), (const));
    MOCK_METHOD(std::string_view, osPlatform, (), (const));
    MOCK_METHOD(std::string_view, osArchitecture, (), (const));
    MOCK_METHOD(std::string_view, osHostName, (), (const));
    MOCK_METHOD(std::string_view, packageName, (), (const));
    MOCK_METHOD(std::string_view, packageVersion, (), (const));
    MOCK_METHOD(std::string_view, packageVendor, (), (const));
    MOCK_METHOD(std::string_view, packageInstallTime, (), (const));
    MOCK_METHOD(uint64_t, packageSize, (), (const));
    MOCK_METHOD(std::string_view, packageFormat, (), (const));
    MOCK_METHOD(std::string_view, packageDescription, (), (const));
    MOCK_METHOD(std::string_view, packageArchitecture, (), (const));
    MOCK_METHOD(std::string_view, packageLocation, (), (const));
    MOCK_METHOD(std::vector<std::string_view>, processArguments, (), (const));
    MOCK_METHOD(std::string_view, processCmdline, (), (const));
    MOCK_METHOD(std::string_view, processName, (), (const));
    MOCK_METHOD(std::string_view, processStartISO8601, (), (const));
    MOCK_METHOD(uint64_t, processParentID, (), (const));

    std::string m_serializedElement;

    // /**
    //  * @brief Mock method
    //  */
    // MOCK_METHOD(void, vendorMaps, (const nlohmann::json& vendor));

    // /**
    //  * @brief Mock method
    //  */
    // MOCK_METHOD(void, osCpeMaps, (const nlohmann::json& osCpe));

    // /**
    //  * @brief Mock method
    //  */
    // MOCK_METHOD(void, cnaMappings, (const nlohmann::json& cna));

    // /**
    //  * @brief Mock method
    //  *
    //  * @return nlohmann::json
    //  */
    // MOCK_METHOD(const nlohmann::json&, vendorMaps, (), (const));

    // /**
    //  * @brief Mock method
    //  *
    //  * @return nlohmann::json
    //  */
    // MOCK_METHOD(const nlohmann::json&, osCpeMaps, (), (const));

    // /**
    //  * @brief Mock method
    //  *
    //  * @return nlohmann::json
    //  */
    // MOCK_METHOD(const nlohmann::json&, cnaMappings, (), (const));

    // /**
    //  * @brief Mock method
    //  *
    //  * @return std::string
    //  */
    // MOCK_METHOD(const std::string&, managerName, (), (const));
};

#endif // _MOCK_SYSTEM_CONTEXT_HPP
