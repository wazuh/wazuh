/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperNetInfoAddress.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperNetInfoAddressTest, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"netInfoAddress"},
                                 std::vector<std::string> {"0"});

    ASSERT_NO_THROW(bld::opBuilderHelperNetInfoAddres(tuple));
}
