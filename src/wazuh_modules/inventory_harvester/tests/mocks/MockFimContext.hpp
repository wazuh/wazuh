/*
 * Wazuh Inventory Harvester - Mock FimContext class
 * Copyright (C) 2015, Wazuh Inc.
 * February 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCK_FIM_CONTEXT_HPP
#define _MOCK_FIM_CONTEXT_HPP

#include "gmock/gmock.h"
#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

/**
 * @brief Mock FimContext class.
 *
 */
class MockFimContext
{
public:
    MockFimContext() = default;
    virtual ~MockFimContext() = default;

    enum class AffectedComponentType : std::uint8_t
    {
        File,
        Registry,
        Invalid
    };

    enum class OriginTable : std::uint8_t
    {
        File,
        RegistryKey,
        RegistryValue,
        Invalid
    };

    MOCK_METHOD(OriginTable, originTable, (), (const));
    MOCK_METHOD(std::string_view, agentId, (), (const));
    MOCK_METHOD(std::string_view, agentName, (), (const));
    MOCK_METHOD(std::string_view, agentIp, (), (const));
    MOCK_METHOD(std::string_view, agentVersion, (), (const));
    MOCK_METHOD(std::string_view, pathRaw, (), (const));
    MOCK_METHOD(std::string_view, valueNameRaw, (), (const));
    MOCK_METHOD(std::string_view, arch, (), (const));
    MOCK_METHOD(std::string_view, md5, (), (const));
    MOCK_METHOD(std::string_view, sha1, (), (const));
    MOCK_METHOD(std::string_view, sha256, (), (const));
    MOCK_METHOD(uint64_t, size, (), (const));
    MOCK_METHOD(uint64_t, inode, (), (const));
    MOCK_METHOD(std::string_view, valueType, (), (const));
    MOCK_METHOD(std::string_view, userName, (), (const));
    MOCK_METHOD(std::string_view, groupName, (), (const));
    MOCK_METHOD(std::string_view, uid, (), (const));
    MOCK_METHOD(std::string_view, gid, (), (const));
    MOCK_METHOD(uint64_t, mtime, (), (const));
    MOCK_METHOD(std::string_view, valueName, (), (const));
    MOCK_METHOD(std::string_view, path, (), (const));
    MOCK_METHOD(std::string_view, mtimeISO8601, (), (const));
    MOCK_METHOD(std::string_view, hive, (), (const));
    MOCK_METHOD(std::vector<std::string_view>, key, (), (const));

    std::string m_serializedElement;
};

#endif // _MOCK_FIM_CONTEXT_HPP
