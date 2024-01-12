/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015, Wazuh Inc.
 * August 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSCOLLECTOR_DELTAS_TEST_H
#define _SYSCOLLECTOR_DELTAS_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "flatbuffers/util.h"

const std::string schemaRootPath {"syscollector_deltas.fbs"};
std::string flatbufferSchemaStr;

class SyscollectorDeltasTest : public ::testing::Test
{
    protected:

        SyscollectorDeltasTest() = default;
        virtual ~SyscollectorDeltasTest() = default;
        /**
         * @brief Initialize string variable with flatbuffer schema.
         */
        static void SetUpTestSuite()
        {
            flatbuffers::LoadFile(schemaRootPath.c_str(), false, &flatbufferSchemaStr);
        }
};

#endif //_SYSCOLLECTOR_DELTAS_TEST_H
