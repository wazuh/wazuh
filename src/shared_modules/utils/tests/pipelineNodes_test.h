/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef PIPELINE_NODE_TESTS_H
#define PIPELINE_NODE_TESTS_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class PipelineNodesTest : public ::testing::Test
{
    protected:

        PipelineNodesTest() = default;
        virtual ~PipelineNodesTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //PIPELINE_NODE_TESTS_H