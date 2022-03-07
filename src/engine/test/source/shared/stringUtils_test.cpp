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

TEST(split, notDelimiter)
{
    std::string test = "test";
    std::vector<std::string> expected = {"test"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, middleDelimiter)
{
    std::string test = "value1/value2";
    std::vector<std::string> expected = {"value1","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, firstDelimiter)
{
    std::string test = "/value1/value2";
    std::vector<std::string> expected = {"","value1","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, finalDelimiter)
{
    std::string test = "value1/value2/";
    std::vector<std::string> expected = {"value1","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, dobleDelimiter)
{
    std::string test = "value1//value2";
    std::vector<std::string> expected = {"value1","","value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, okDelimiter)
{
    std::string test = "value1/value2/value3";
    std::vector<std::string> expected = {"value1","value2","value3"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}
