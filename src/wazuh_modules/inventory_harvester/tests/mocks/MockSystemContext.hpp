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
        Hotfixes,
        Hw,
        Ports,
        NetworkProtocol,
        NetIfaces,
        NetAddress,
        Users,
        Groups,
        Invalid
    };

    enum class AffectedComponentType : std::uint8_t
    {
        Package,
        Process,
        System,
        Port,
        Hotfix,
        Hardware,
        NetProto,
        NetIface,
        NetworkAddress,
        User,
        Group,
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
    MOCK_METHOD(std::string_view, osKernelVersion, (), (const));
    MOCK_METHOD(std::string_view, osPlatform, (), (const));
    MOCK_METHOD(std::string_view, osArchitecture, (), (const));
    MOCK_METHOD(std::string_view, osHostName, (), (const));
    MOCK_METHOD(std::string_view, osCodeName, (), (const));
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
    // Ports
    MOCK_METHOD(std::string_view, portProtocol, (), (const));
    MOCK_METHOD(std::string_view, portLocalIp, (), (const));
    MOCK_METHOD(int64_t, portLocalPort, (), (const));
    MOCK_METHOD(int64_t, portInode, (), (const));
    MOCK_METHOD(std::string_view, portRemoteIp, (), (const));
    MOCK_METHOD(int64_t, portRemotePort, (), (const));
    MOCK_METHOD(int64_t, portTxQueue, (), (const));
    MOCK_METHOD(int64_t, portRxQueue, (), (const));
    MOCK_METHOD(std::string_view, portState, (), (const));
    MOCK_METHOD(std::string_view, portProcess, (), (const));
    MOCK_METHOD(int64_t, portPid, (), (const));
    MOCK_METHOD(std::string_view, portItemId, (), (const));

    // Networks
    MOCK_METHOD(std::string_view, netAddressItemId, (), (const));
    MOCK_METHOD(std::string_view, broadcast, (), (const));
    MOCK_METHOD(std::string_view, netAddressName, (), (const));
    MOCK_METHOD(std::string_view, netmask, (), (const));
    MOCK_METHOD(int64_t, protocol, (), (const));
    MOCK_METHOD(std::string_view, address, (), (const));

    MOCK_METHOD(std::string_view, hotfixName, (), (const));
    MOCK_METHOD(std::string_view, boardInfo, (), (const));
    MOCK_METHOD(int64_t, cpuCores, (), (const));
    MOCK_METHOD(std::string_view, cpuName, (), (const));
    MOCK_METHOD(int64_t, cpuFrequency, (), (const));
    MOCK_METHOD(int64_t, freeMem, (), (const));
    MOCK_METHOD(int64_t, totalMem, (), (const));
    MOCK_METHOD(double, usedMem, (), (const));
    MOCK_METHOD(std::string_view, netProtoIface, (), (const));
    MOCK_METHOD(std::string_view, netProtoType, (), (const));
    MOCK_METHOD(std::string_view, netProtoGateway, (), (const));
    MOCK_METHOD(std::string_view, netProtoDhcp, (), (const));
    MOCK_METHOD(int64_t, netProtoMetric, (), (const));
    MOCK_METHOD(std::string_view, netProtoItemId, (), (const));

    MOCK_METHOD(AffectedComponentType, affectedComponentType, (), (const));

    // NetIface
    MOCK_METHOD(std::string_view, netIfaceName, (), (const));
    MOCK_METHOD(std::string_view, netIfaceMac, (), (const));
    MOCK_METHOD(int64_t, netIfaceRxBytes, (), (const));
    MOCK_METHOD(int64_t, netIfaceRxDrops, (), (const));
    MOCK_METHOD(int64_t, netIfaceRxErrors, (), (const));
    MOCK_METHOD(int64_t, netIfaceRxPackets, (), (const));
    MOCK_METHOD(int64_t, netIfaceTxBytes, (), (const));
    MOCK_METHOD(int64_t, netIfaceTxDrops, (), (const));
    MOCK_METHOD(int64_t, netIfaceTxErrors, (), (const));
    MOCK_METHOD(int64_t, netIfaceTxPackets, (), (const));
    MOCK_METHOD(std::string_view, netIfaceAdapter, (), (const));
    MOCK_METHOD(int64_t, netIfaceMtu, (), (const));
    MOCK_METHOD(std::string_view, netIfaceState, (), (const));
    MOCK_METHOD(std::string_view, netIfaceType, (), (const));
    MOCK_METHOD(std::string_view, netIfaceItemId, (), (const));

    // Users
    MOCK_METHOD(std::string_view, userName, (), (const));
    MOCK_METHOD(int, userId, (), (const));
    MOCK_METHOD(int, userUidSigned, (), (const));
    MOCK_METHOD(int, userGroupId, (), (const));
    MOCK_METHOD(int, userGroupIdSigned, (), (const));
    MOCK_METHOD(std::string_view, userHome, (), (const));
    MOCK_METHOD(std::string_view, userShell, (), (const));
    MOCK_METHOD(std::string_view, userType, (), (const));
    MOCK_METHOD(std::string_view, userUuid, (), (const));
    MOCK_METHOD(std::string_view, userFullName, (), (const));
    MOCK_METHOD(bool, userIsHidden, (), (const));
    MOCK_METHOD(bool, userIsRemote, (), (const));
    MOCK_METHOD(std::string_view, userPasswordHashAlgorithm, (), (const));
    MOCK_METHOD(int, userPasswordMaxDays, (), (const));
    MOCK_METHOD(int, userPasswordMinDays, (), (const));
    MOCK_METHOD(int, userPasswordWarningDays, (), (const));
    MOCK_METHOD(std::string_view, userPasswordStatus, (), (const));
    MOCK_METHOD(std::string_view, userPasswordLastChange, (), (const));
    MOCK_METHOD(std::string_view, userPasswordExpirationDate, (), (const));
    MOCK_METHOD(int, userPasswordInactiveDays, (), (const));
    MOCK_METHOD(std::string_view, userCreated, (), (const));
    MOCK_METHOD(std::string_view, userLastLogin, (), (const));
    MOCK_METHOD(std::string_view, userRoles, (), (const));
    MOCK_METHOD(std::string_view, userGroups, (), (const));
    MOCK_METHOD(int, userAuthFailedCount, (), (const));
    MOCK_METHOD(std::string_view, userAuthFailedTimestamp, (), (const));
    MOCK_METHOD(bool, userLoginStatus, (), (const));
    MOCK_METHOD(std::string_view, userLoginType, (), (const));
    MOCK_METHOD(std::string_view, userLoginTty, (), (const));
    MOCK_METHOD(int64_t, userProcessPid, (), (const));
    MOCK_METHOD(std::string_view, userHostIp, (), (const));

    // Groups
    MOCK_METHOD(std::string_view, groupName, (), (const));
    MOCK_METHOD(int64_t, groupId, (), (const));
    MOCK_METHOD(int64_t, groupIdSigned, (), (const));
    MOCK_METHOD(std::string_view, groupDescription, (), (const));
    MOCK_METHOD(std::string_view, groupUuid, (), (const));
    MOCK_METHOD(bool, groupIsHidden, (), (const));
    MOCK_METHOD(std::string_view, groupUsers, (), (const));

    std::string m_serializedElement;
};

#endif // _MOCK_SYSTEM_CONTEXT_HPP
