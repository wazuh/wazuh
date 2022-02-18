/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "threadingTest.hpp"

using std::function;
using std::ostringstream;
using std::string;
using std::thread;
using std::to_string;
using std::vector;
using threadpool::threadPool;

using rxcpp::composite_subscription;
using rxcpp::observable;

TEST(RxcppThreading, test)
{
    rxcpp::schedulers::run_loop rl;
    std::shared_ptr<uvw::Loop> uvloop = uvw::Loop::getDefault();
    std::shared_ptr<uvw::TCPHandle> tcpServer = uvloop->resource<uvw::TCPHandle>();
    const std::string address = std::string{"127.0.0.1"};
    const unsigned int port = 5054;

    printsafe("Start task");

    auto nThreads = 5;
    auto nEvents = 15;

    auto mainThread = rxcpp::observe_on_run_loop(rl);
    auto poolThread = rxcpp::observe_on_event_loop();
    auto coord = rxcpp::schedulers::make_scheduler<threadPool>(nThreads,
                                                               //  lambda is the thread pool factory
                                                               // f is the task issued by rxcpp
                                                               [&](function<void()> f) -> thread
                                                               {
                                                                   // Thread pool implementation goes here
                                                                   thread t(f);
                                                                   ostringstream ss;
                                                                   ss << t.get_id();
                                                                   string idstr = ss.str();
                                                                   printsafe("ThreadPool created " + idstr);
                                                                   return t;
                                                               });

    vector<observable<int>> events;
    for (auto i = 0; i < nEvents; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events, mainThread);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(coord.create_worker())); })
        .subscribe([](auto o) { printsafe("Got event " + to_string(o)); });

    composite_subscription lifetime;

    if (lifetime.is_subscribed())
    {
        printsafe("Tick Main");
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            printsafe("Tick Dispatch");
            rl.dispatch();
        }
    }

    printsafe("End task");
}
