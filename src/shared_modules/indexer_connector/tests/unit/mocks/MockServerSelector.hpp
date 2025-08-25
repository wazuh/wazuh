/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * July 7, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
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

    // Default constructor for GMock
    MockServerSelector() = default;

    // Mock constructor - GMock doesn't mock constructors, so we provide a simple stub
    MockServerSelector(const std::vector<std::string>&, uint32_t, const SecureCommunication&)
    {
        // Mock constructor - does nothing real
    }
};

#endif // _MOCK_SERVER_SELECTOR_HPP
