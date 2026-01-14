/*
 * Wazuh SyscollectorImp
 * Copyright (C) 2015, Wazuh Inc.
 * November 9, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_IMP_TEST_H
#define _SYSCOLLECTOR_IMP_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <memory>

// Forward declaration
class MockSchemaValidatorEngine;

class SyscollectorImpTest : public ::testing::Test
{
    protected:

        SyscollectorImpTest() = default;
        virtual ~SyscollectorImpTest() = default;

        void SetUp() override;
        void TearDown() override;

        // Store mock validator to keep it alive during test execution
        std::shared_ptr<MockSchemaValidatorEngine> m_mockValidator;
};

#endif //_SYSCOLLECTOR_IMP_TEST_H