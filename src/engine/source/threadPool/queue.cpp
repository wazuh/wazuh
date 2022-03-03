/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "queue.hpp"

namespace threadpool
{
rigtorp::MPMCQueue<std::string> queue(1000);
moodycamel::BlockingConcurrentQueue<std::string> queue2{1000};
// rxcpp::schedulers::scheduler sc = rxcpp::schedulers::make_scheduler<ThreadPool>(3);
// rxcpp::observe_on_one_worker threadPoolW(sc); // TODO: Find a way to not to use the static in here
// rxcpp::schedulers::run_loop rl;
// auto mainLoop = rxcpp::observe_on_run_loop(rl);
} // namespace threadpool
