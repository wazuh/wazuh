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
//using threadpool::threadPool;

using rxcpp::composite_subscription;
using rxcpp::observable;

#define WAIT_FOR_WORKERS_TIME_MS    50

TEST(RxcppThreading, testSchedulerCustomFactoryWithPrints)
{
    printsafe("Start task");

    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 5;
    auto nEvents = 26;

    auto eventScheduler =
        rxcpp::schedulers::make_scheduler<threadPool>(nThreads,
                                                      // lambda of the threadpool factory, f is the task issued by rxcpp
                                                      [&](function<void()> f) -> thread
                                                      {
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

    auto serverFactory = observable<>::iterate(events);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(eventScheduler.create_worker())); })
        .subscribe(
            [&](auto o)
            {
                printsafe("Got event " + to_string(o));
                events_count++;
            });

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

    // Replace with an automated check for jobs consumed.
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);

    printsafe("End task");
}

TEST(RxcppThreading, testScheduler_1threads_10events)
{
    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 1;
    auto nEvents = 10;

    auto eventScheduler = rxcpp::schedulers::make_scheduler<threadPool>(nThreads);

    vector<observable<int>> events;

    for (auto i = 0; i < nEvents; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(eventScheduler.create_worker())); })
        .subscribe([&](auto o) { events_count++; });

    composite_subscription lifetime;

    if (lifetime.is_subscribed())
    {
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            rl.dispatch();
        }
    }

    // Replace with an automated check for jobs consumed.
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testScheduler_6threads_60events)
{
    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 6;
    auto nEvents = 60;

    auto eventScheduler = rxcpp::schedulers::make_scheduler<threadPool>(nThreads);

    vector<observable<int>> events;

    for (auto i = 0; i < nEvents; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(eventScheduler.create_worker())); })
        .subscribe([&](auto o) { events_count++; });

    composite_subscription lifetime;

    if (lifetime.is_subscribed())
    {
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            rl.dispatch();
        }
    }

    // Replace with an automated check for jobs consumed.
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testScheduler_5threads_50events)
{
    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 5;
    auto nEvents = 50;

    auto eventScheduler = rxcpp::schedulers::make_scheduler<threadPool>(nThreads);

    vector<observable<int>> events;

    for (auto i = 0; i < nEvents; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(eventScheduler.create_worker())); })
        .subscribe([&](auto o) { events_count++; });

    composite_subscription lifetime;

    if (lifetime.is_subscribed())
    {
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            rl.dispatch();
        }
    }

    // Replace with an automated check for jobs consumed.
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testScheduler_15threads_40events)
{
    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 15;
    auto nEvents = 40;

    auto eventScheduler = rxcpp::schedulers::make_scheduler<threadPool>(nThreads);

    vector<observable<int>> events;

    for (auto i = 0; i < nEvents; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(eventScheduler.create_worker())); })
        .subscribe([&](auto o) { events_count++; });

    composite_subscription lifetime;

    if (lifetime.is_subscribed())
    {
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            rl.dispatch();
        }
    }

    // Replace with an automated check for jobs consumed.
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testWithFactory)
{
    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 5;
    auto nEvents = 50;

    auto eventScheduler =
        rxcpp::schedulers::make_scheduler<threadPool>(nThreads,
                                                      // lambda of the threadpool factory, f is the task issued by rxcpp
                                                      [&](function<void()> f) -> thread { return thread{f}; });

    vector<observable<int>> events;
    for (auto i = 0; i < nEvents; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(eventScheduler.create_worker())); })
        .subscribe([&](auto o) { events_count++; });

    composite_subscription lifetime;

    if (lifetime.is_subscribed())
    {
        while (!rl.empty() && rl.peek().when < rl.now())
        {
            rl.dispatch();
        }
    }

    // Replace with an automated check for jobs consumed.
    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}
