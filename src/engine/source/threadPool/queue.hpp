/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _QUEUE_H
#define _QUEUE_H

#include "threadPool.hpp"
#include <MPMCQueue.h>
#include <blockingconcurrentqueue.h>
#include <rxcpp/rx.hpp>
#include <string>

namespace threadpool
{
    extern moodycamel::BlockingConcurrentQueue<std::string> queue2;
    extern rigtorp::MPMCQueue<std::string> queue;
} // namespace threadpool

#endif // _QUEUE_H
