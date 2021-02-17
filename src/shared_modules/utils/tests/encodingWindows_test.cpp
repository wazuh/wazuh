/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
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
    test["correct"] = Utils::EncodingWindowsHelper::wstringToStringUTF8(L"������");

    EXPECT_NO_THROW(test.dump());
}

#endif