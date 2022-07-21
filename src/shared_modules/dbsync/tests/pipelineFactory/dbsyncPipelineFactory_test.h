/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef DBSYNC_PIPELINE_FACTORY_TESTS_H
#define DBSYNC_PIPELINE_FACTORY_TESTS_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class DBSyncPipelineFactoryTest : public ::testing::Test
{
    protected:

        DBSyncPipelineFactoryTest()
            : m_pipelineFactory{DbSync::PipelineFactory::instance()}
            , m_dbHandle{ nullptr }
        {}
        virtual ~DBSyncPipelineFactoryTest() = default;

        void SetUp() override;
        void TearDown() override;
        DbSync::PipelineFactory& m_pipelineFactory;
        DBSYNC_HANDLE m_dbHandle;
};
#endif //DBSYNC_PIPELINE_FACTORY_TESTS_H