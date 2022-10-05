/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include <logging/logging.hpp>
#include <wdb/wdb.hpp>

#include "opBuilderHelperActiveResponse.hpp"
#include "socketAuxiliarFunctions.hpp"

using namespace base;
using namespace builder::internals::builders;

using std::string;

const string targetField {"/result"};
const string helperFunctionName {"ar_create"};
const std::vector<string> commonArguments {"$event","command-name", "LOCAL", "100","$_argvs"};

class opBuilderHelperCreateARTest : public ::testing::Test
{
protected:
    const fmtlog::LogLevel logLevel {fmtlog::getLogLevel()};

    void SetUp() override
    {
        // Disable error logs for these tests
        fmtlog::setLogLevel(fmtlog::LogLevel(logging::LogLevel::Off));
    }

    void TearDown() override
    {
        // Restore original log level
        fmtlog::setLogLevel(fmtlog::LogLevel(logLevel));
    }
};

TEST_F(opBuilderHelperCreateARTest, BuildSimplest)
{
    const auto tuple {std::make_tuple(targetField, helperFunctionName, commonArguments)};

    ASSERT_NO_THROW(opBuilderHelperCreateAR(tuple));
}

TEST_F(opBuilderHelperCreateARTest, checkWrongQttyParamsLess)
{
    const std::vector<string> arguments {"$event"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderHelperCreateAR(tuple), std::runtime_error);
}

TEST_F(opBuilderHelperCreateARTest, checkWrongQttyParamsMore)
{
    const std::vector<string> arguments {"$event","command-name", "LOCAL", "100","$_argvs","extra"};

    const auto tuple {std::make_tuple(targetField, helperFunctionName, arguments)};

    ASSERT_THROW(opBuilderHelperCreateAR(tuple), std::runtime_error);
}
