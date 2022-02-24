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
#include <sstream>
#include <cstdlib>

#include "threadPool.hpp"

#define GTEST_COUT std::cout << "[   INFO   ] "

using threadpool::ThreadPool;
using namespace std;
namespace Rx{
    using namespace rxcpp;
    using namespace rxcpp::subjects;
    using namespace rxcpp::schedulers;
    namespace rxo = rxcpp::operators;
    namespace rxu = rxcpp::util;
}
using namespace Rx;

void printsafe(string s)
{
    static mutex m;
    m.lock();
    GTEST_COUT << "[thread " << this_thread::get_id() << "] " << s << endl;
    m.unlock();
}

#endif
