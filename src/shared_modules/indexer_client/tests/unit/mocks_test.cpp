/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include <memory>

#include <gtest/gtest.h>

#include "mockIndexerClient.hpp"

using namespace indexer_client;
using ::testing::_;
using ::testing::Return;

TEST(MocksTest, CompileAndExpect)
{
    MockWriter writer;
    EXPECT_CALL(writer, cancel(_)).WillOnce(Return(CancelTicket {}));
    EXPECT_FALSE(writer.cancel("tag").ready());

    MockQuery query;
    EXPECT_CALL(query, indexExists(_, _, _)).WillOnce(Return(Outcome<bool> {true}));
    EXPECT_TRUE(query.indexExists("index", QueryOptions {}, Deadline {}).value);

    MockClient client;
    EXPECT_CALL(client, requestClose()).Times(1);
    client.requestClose();
}
