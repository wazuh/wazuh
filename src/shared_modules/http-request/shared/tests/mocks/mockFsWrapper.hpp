/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Jul 10, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MOCKFSWRAPPER_HPP
#define _MOCKFSWRAPPER_HPP

#include <gmock/gmock.h>
/**
 * @brief This class is a wrapper for the filesystem library.
 */
class MockFsWrapper
{
public:
    MockFsWrapper() = default;
    virtual ~MockFsWrapper() = default;

    /**
     * @brief Mock method to check if a file exists.
     */
    MOCK_METHOD(bool, exists, (const std::string& path));
};

#endif // _MOCKFSWRAPPER_HPP

