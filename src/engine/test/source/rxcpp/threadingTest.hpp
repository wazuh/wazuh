/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _THREADING_TEST_HPP_
#define _THREADING_TEST_HPP_

#include <chrono>
#include <gtest/gtest.h>
#include <mutex>
#include <rxcpp/rx.hpp>
#include <thread>
#include <uvw/tcp.hpp>

#include "threadPool.hpp"

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

void printsafe(std::string s)
{
    static std::mutex m;
    m.lock();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] " << s << std::endl;
    m.unlock();
}

#endif
