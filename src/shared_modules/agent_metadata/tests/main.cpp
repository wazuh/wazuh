/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#ifndef _WIN32
#include <cstdlib>
#include <cstring>
#include "metadata_provider.h"

// Read by the atexit-ordering test, which re-executes this binary in child mode.
const char* g_testBinaryPath = nullptr;

namespace
{
    // Stands in for agentd's shutdown drain, which reads the provider from an exit
    // handler registered before the provider existed.
    void readMetadataAtExit()
    {
        agent_metadata_t metadata{};
        metadata_provider_get(&metadata);
        metadata_provider_free_metadata(&metadata);
    }

    // Child half of ReadFromAtexitAfterProviderTeardownDoesNotCrash (#38766). Needs a
    // freshly executed process: by the time a test body runs, the fixture's SetUp() has
    // already constructed the singleton and the ordering no longer exists.
    int runAtexitChild()
    {
        // Registered before the provider exists, as agentd does.
        if (std::atexit(readMetadataAtExit) != 0)
        {
            return 2;
        }

        agent_metadata_t metadata{};
        std::strncpy(metadata.agent_id, "001", sizeof(metadata.agent_id) - 1);

        if (metadata_provider_update(&metadata) != 0)
        {
            return 3;
        }

        return 0;
    }
}
#endif

int main(int argc, char** argv)
{
#ifndef _WIN32

    if (std::getenv("WAZUH_METADATA_ATEXIT_CHILD") != nullptr)
    {
        return runAtexitChild();
    }

    g_testBinaryPath = argv[0];
#endif

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
