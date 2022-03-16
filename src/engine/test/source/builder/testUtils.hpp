/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

// Shared dependencies for Builder module
#include <rxcpp/rx.hpp>

#include "builderTypes.hpp"
#include "registry.hpp"
#include "json.hpp"

#define GTEST_COUT std::cout << std::boolalpha << "[          ] [ INFO ] "

using namespace std;
using namespace rxcpp;
using namespace builder::internals;
using namespace builder::internals::types;

#endif // _TEST_UTILS_H
