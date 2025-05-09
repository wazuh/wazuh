/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * March 18, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef REFLECTIVE_JSON_HPP
#define REFLECTIVE_JSON_HPP

#include "gtest/gtest.h"

class ReflectiveJsonTest : public ::testing::Test
{
protected:
    ReflectiveJsonTest() = default;
    virtual ~ReflectiveJsonTest() = default;

    void SetUp() override;
    void TearDown() override;
};
#endif // REFLECTIVE_JSON_HPP
