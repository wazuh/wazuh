/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PUB_SUB_PUBLISHER_TEST_HPP
#define _PUB_SUB_PUBLISHER_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for PubSubPublisher
 */
class PubSubPublisherTest : public ::testing::Test
{
protected:
    PubSubPublisherTest() = default;
    ~PubSubPublisherTest() override = default;
};

#endif //_PUB_SUB_PUBLISHER_TEST_HPP
