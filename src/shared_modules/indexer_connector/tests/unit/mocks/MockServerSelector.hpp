/*
 * Wazuh - Indexer connector.
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _MOCK_SERVER_SELECTOR_HPP
#define _MOCK_SERVER_SELECTOR_HPP

#include "secureCommunication.hpp"
#include <gmock/gmock.h>
#include <string>
#include <vector>

/**
 * @brief GMock-based mock for ServerSelector class
 *
 * This mock replaces the custom MockServerSelector class with a proper GMock implementation.
 */
class MockServerSelector
{
public:
    MOCK_METHOD(std::string, getNext, (), ());
    MOCK_METHOD(bool, isAvailable, (), ());

    // Default constructor for GMock
    MockServerSelector() = default;

    // Mock constructor - GMock doesn't mock constructors, so we provide a simple stub
    MockServerSelector(const std::vector<std::string>&, uint32_t, const SecureCommunication&)
    {
        // Mock constructor - does nothing real
    }
};

#endif // _MOCK_SERVER_SELECTOR_HPP
