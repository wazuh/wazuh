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
TEST(opBuilderKVDBExtract, Builds)
{
    Document doc{R"({
        "map":
            {"field2extract": "+kvdb_extract/DB/ref_key"}
    })"};
    ASSERT_NO_THROW(opBuilderKVDBExtract(*doc.get("/map")));
}
