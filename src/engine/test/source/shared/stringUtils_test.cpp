/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <vector>

#include "stringUtils.hpp"

TEST(split, not_delimiter)
{
    std::string test = "test";
    std::vector<std::string> expected = {"test"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, middle_delimiter)
{
    std::string test = "value1/value2";
    std::vector<std::string> expected = {"value1","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, first_delimiter)
{
    std::string test = "/value1/value2";
    std::vector<std::string> expected = {"","value1","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, final_delimiter)
{
    std::string test = "value1/value2/";
    std::vector<std::string> expected = {"value1","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, doble_delimiter)
{
    std::string test = "value1//value2";
    std::vector<std::string> expected = {"value1","","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, ok_delimiter)
{
    std::string test = "value1/value2/value3";
    std::vector<std::string> expected = {"value1","value2","value3"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}
