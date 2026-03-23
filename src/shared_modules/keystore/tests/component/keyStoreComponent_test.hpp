/*
 * Wazuh keystore
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _KEYSTORE_COMPONENT_TEST_HPP
#define _KEYSTORE_COMPONENT_TEST_HPP

#include <gtest/gtest.h>

/**
 * @brief KeyStoreComponentTest class.
 *
 */
class KeyStoreComponentTest : public ::testing::Test
{
protected:
    KeyStoreComponentTest() = default;
    ~KeyStoreComponentTest() override = default;
};
#endif //_KEYSTORE_COMPONENT_TEST_HPP
