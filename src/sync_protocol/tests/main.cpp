/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <iostream>
#include "logging_helper.hpp"

int main(int argc, char** argv)
{
  // Forward logs to stdout to avoid exceptions
  LoggingHelper::setLogCallback([](modules_log_level_t, const char* log) {
    std::cout << log << std::endl;
  });

  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
