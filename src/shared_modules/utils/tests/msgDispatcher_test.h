/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Sep 1, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MSG_DISPATCHER_TESTS_H
#define MSG_DISPATCHER_TESTS_H
#include "gmock/gmock.h"
#include "gtest/gtest.h"

class MsgDispatcherTest : public ::testing::Test
{
protected:
    MsgDispatcherTest() = default;
    virtual ~MsgDispatcherTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // MSG_DISPATCHER_TESTS_H
