/*
 * Wazuh app - Command line helper
 * Copyright (C) 2015, Wazuh Inc.
 * June 17, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cmdLineHelper_test.h"
#include "cmdLineHelper.hpp"

void CmdLineHelperTest::SetUp() {};

void CmdLineHelperTest::TearDown() {};

TEST_F(CmdLineHelperTest, dryRunFlagTrue)
{
    const char* argv[] = {"./dbsync_test_tool","-t","nvd","-i","input1.json","-o","./output","-b"};

std::cout<<sizeof(argv)/sizeof(argv[0])<<'\n';
    CmdLineArgs cmdLineArgs(sizeof(argv)/sizeof(argv[0]), argv);

    std::cout<<"B:"<<cmdLineArgs.beautify();
    EXPECT_EQ(2, cmdLineArgs.beautify());
}
