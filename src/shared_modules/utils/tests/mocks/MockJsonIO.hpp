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
#ifndef _MOCKJSONIO_HPP
#define _MOCKJSONIO_HPP

#include "json.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <filesystem>

class MockJsonIO
{
public:
    MOCK_METHOD(nlohmann::json, readJson, (const std::filesystem::path&), ());
};

#endif // _MOCKJSONIO_HPP
