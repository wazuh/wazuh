/**
 * Wazuh Inventory Sync - ResponseDispatcher Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "flatbuffers/flatbuffers.h"
#include "responseDispatcher.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace ::testing;

// Mock for the TQueue
class MockResponseQueue
{
public:
    MOCK_METHOD(void, push, (ResponseMessage && message));
};

class ResponseDispatcherTest : public ::testing::Test
{
protected:
    using ResponseDispatcherForTest = ResponseDispatcherImpl<MockResponseQueue>;
};

// TODO(#38117): StartAck/EndAck removed from FlatBuffer schema/agent side - the manager
// no longer acknowledges sessions via either, so ResponseDispatcherImpl has no methods
// left to test here. The real /stateful HTTP response is the server team's own follow-up.
