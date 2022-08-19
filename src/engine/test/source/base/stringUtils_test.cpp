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

#include <utils/stringUtils.hpp>

TEST(split, null_del)
{
    std::string test = "test";
    std::vector<std::string> expected = {"test"};
    std::vector<std::string> result = utils::string::split(test, '\0');
    ASSERT_EQ(result, expected);
}

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
    std::vector<std::string> expected = {"value1", "value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, first_delimiter)
{
    std::string test = "/value1/value2";
    std::vector<std::string> expected = {"", "value1", "value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, final_delimiter)
{
    std::string test = "value1/value2/";
    std::vector<std::string> expected = {"value1", "value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, doble_delimiter)
{
    std::string test = "value1//value2";
    std::vector<std::string> expected = {"value1", "", "value2"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(split, ok_delimiter)
{
    std::string test = "value1/value2/value3";
    std::vector<std::string> expected = {"value1", "value2", "value3"};
    std::vector<std::string> result = utils::string::split(test, '/');
    ASSERT_EQ(result, expected);
}

TEST(splitMulti, ThreeDelimiters) {
    std::string input = "this is-a test to split by - and ,,where-are included in the result";
    std::vector<std::string> expected = {"this", "is", "-", "a", "test", "to", "split", "by", "-", "and", "where", "-", "are", "included", "in", "the", "result"};
    std::vector<std::string> result = utils::string::splitMulti(input, utils::string::Delimeter('-', true), utils::string::Delimeter(',', false), utils::string::Delimeter(' ', false));
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator)
{
    const std::string expected = "test";
    const std::vector<std::string> test = {"test"};
    const std::string result = utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(join, not_defaut_separator_starting_with_it)
{
    const std::string expected = ",test";
    const std::string separator = ",";
    const std::vector<std::string> test = {"test"};
    std::string result = utils::string::join(test, separator, true);
    ASSERT_EQ(result, expected);
}

TEST(join, not_defaut_separator_several_strings_starting_with_it)
{
    const std::string expected = ",test1,test2,test3,test4";
    const std::string separator = ",";
    const std::vector<std::string> test = {"test1", "test2", "test3", "test4"};
    std::string result = utils::string::join(test, separator, true);
    ASSERT_EQ(result, expected);
}

TEST(join, not_defaut_separator_several_strings)
{
    const std::string expected = "test1,test2,test3,test4";
    const std::string separator = ",";
    const std::vector<std::string> test = {"test1", "test2", "test3", "test4"};
    std::string result = utils::string::join(test, separator, false);
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator_several_strings)
{
    const std::string expected = "test1test2test3test4";
    const std::vector<std::string> test = {"test1", "test2", "test3", "test4"};
    const std::string result = utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator_none_input)
{
    const std::string expected = "";
    const std::vector<std::string> test = {};
    const std::string result = utils::string::join(test);
    ASSERT_EQ(result, expected);
}

TEST(join, defaut_separator_empty_strings_array_as_input)
{
    const std::string expected = "";
    const std::vector<std::string> test = {"", "", ""};
    const std::string result = utils::string::join(test);
    ASSERT_EQ(result, expected);
}
