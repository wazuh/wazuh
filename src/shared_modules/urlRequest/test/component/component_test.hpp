/*
 * Wazuh URLRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 18, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMPONENT_TEST_H
#define _COMPONENT_TEST_H

#include <memory>
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#include "httplib.h"
#pragma GCC diagnostic pop

#include "HTTPRequest.hpp"

class ComponentTestInterface : public ::testing::Test
{
    protected:

        ComponentTestInterface() = default;
        virtual ~ComponentTestInterface() = default;

        void SetUp() override;
        void TearDown() override;
};

class ComponentTestInternalParameters : public ::testing::Test
{
    protected:

        ComponentTestInternalParameters() = default;
        virtual ~ComponentTestInternalParameters() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif // _COMPONENT_TEST_H


