/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * February 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WIN32
#include "encodingWindows_test.h"
#include "encodingWindowsHelper.h"
#include "json.hpp"

void EncodingWindowsHelperTest::SetUp() {};

void EncodingWindowsHelperTest::TearDown() {};

TEST_F(EncodingWindowsHelperTest, NoExceptConversion)
{
    nlohmann::json test;
    std::wstring wideString = L"Eines de correcció del Microsoft Office 2016: català";
    std::string multibyteString;
    multibyteString.assign(wideString.begin(), wideString.end());
    test["correct"] = Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(multibyteString);
    EXPECT_NO_THROW(test.dump());
}

TEST_F(EncodingWindowsHelperTest, ExceptWithoutConversion)
{
    nlohmann::json test;
    std::wstring wideString = L"Eines de correcció del Microsoft Office 2016: català";
    std::string multibyteString;
    multibyteString.assign(wideString.begin(), wideString.end());
    test["incorrect"] = multibyteString;
    EXPECT_ANY_THROW(test.dump());
}

TEST_F(EncodingWindowsHelperTest, ReturnValueEmptyConversion)
{
    EXPECT_EQ(Utils::EncodingWindowsHelper::stringAnsiToStringUTF8(""), "");
}

#endif