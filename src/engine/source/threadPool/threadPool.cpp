/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "threadPool.hpp"

using namespace threadpool;

void threadPool::initThreads(void)
{
    // auto remaining = std::max(std::thread::hardware_concurrency(), unsigned(4));
    auto remaining = nThreads > 1 ? nThreads : 1;
    while (remaining--)
    {
        loops.push_back(newthread.create_worker(loops_lifetime));
    }
}
