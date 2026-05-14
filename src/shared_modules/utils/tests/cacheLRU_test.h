/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CACHE_LRU_TESTS_H
#define CACHE_LRU_TESTS_H
#include "gtest/gtest.h"

class CacheLRUTest : public ::testing::Test
{
    protected:

        CacheLRUTest() = default;
        virtual ~CacheLRUTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //CACHE_LRU_TESTS_H
