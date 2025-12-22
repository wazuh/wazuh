/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _MOCKFILEIO_HPP
#define _MOCKFILEIO_HPP

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>

class MockFileIO
{
public:
    MOCK_METHOD(void,
                readLineByLine,
                (const std::filesystem::path&, const std::function<bool(const std::string&)>&),
                ());
};

#endif // _MOCKFILEIO_HPP
