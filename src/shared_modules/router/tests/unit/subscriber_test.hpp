/*
 * Wazuh router - Subscriber tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SUBSCRIBER_TEST_HPP
#define _SUBSCRIBER_TEST_HPP

#include <gtest/gtest.h>

/**
 * @brief Runs unit tests for Subscriber class
 */
class SubscriberTest : public ::testing::Test
{
protected:
    SubscriberTest() = default;
    ~SubscriberTest() override = default;
};

#endif //_SUBSCRIBER_TEST_HPP
