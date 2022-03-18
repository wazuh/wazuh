/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <vector>
#include <gtest/gtest.h>
#include "testUtils.hpp"
#include "opBuilderKVDB.hpp"

using namespace builder::internals::builders;

// Build ok
TEST(opBuilderKVDBMatch, Builds)
{
    Document doc{R"({
        "check":
            {"field2match": "+kvdb_match/DB"}
    })"};
    ASSERT_NO_THROW(opBuilderKVDBMatch(*doc.get("/check")));
}

TEST(opBuilderKVDBNotMatch, Builds)
{
    Document doc{R"({
        "check":
            {"field2match": "+kvdb_not_match/DB"}
    })"};
    ASSERT_NO_THROW(opBuilderKVDBNotMatch(*doc.get("/check")));
}
