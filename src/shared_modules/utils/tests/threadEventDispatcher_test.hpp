/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _THREAD_EVENT_DISPATCHER_TEST_HPP
#define _THREAD_EVENT_DISPATCHER_TEST_HPP

#include "rocksDBQueue.hpp"
#include "threadSafeQueue.h"
#include <gtest/gtest.h>
#include <memory>
#include <thread>

class ThreadEventDispatcherTest : public ::testing::Test
{
protected:
    ThreadEventDispatcherTest() = default;
    ~ThreadEventDispatcherTest() override = default;
    void SetUp() override;
    void TearDown() override;
};
#endif //_THREAD_EVENT_DISPATCHER_TEST_HPP
