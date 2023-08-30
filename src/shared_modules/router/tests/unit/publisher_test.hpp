/*
 * Wazuh router - Publisher tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PUBLISHER_TEST_HPP
#define _PUBLISHER_TEST_HPP

#include <gtest/gtest.h>

/**
 * @brief Runs unit tests for Publisher class
 */
class PublisherTest : public ::testing::Test
{
protected:
    PublisherTest() = default;
    ~PublisherTest() override = default;
};

#endif //_PUBLISHER_TEST_HPP
