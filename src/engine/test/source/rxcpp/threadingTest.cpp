/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "threadingTest.hpp"
#include <sstream>

using std::function;
using std::ostringstream;
using std::string;
using std::thread;
using std::to_string;
using std::vector;
using threadpool::ThreadPool;

using rxcpp::composite_subscription;
using rxcpp::observable;

#define WAIT_FOR_WORKERS_TIME_MS 50

TEST(RxcppThreading, testSchedulerCustomFactoryWithPrints)
{
    printsafe("Start task");

    rxcpp::schedulers::run_loop rl;

    std::atomic<int> events_count = 0;

    auto nThreads = 5;
    auto nEvents = 26;

    auto eventScheduler =
        rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads,
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

    auto eventScheduler = rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads);

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

    auto eventScheduler = rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads);

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

    auto eventScheduler = rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads);

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

    auto eventScheduler = rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads);

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
        rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads,
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

using namespace rxcpp::operators;
TEST(RxcppThreading, SubscriberSubjectx100000)
{
    struct event
    {
        std::thread::id pipeId;
        int e;
        void check(std::thread::id other)
        {
            std::stringstream s1;
            std::stringstream s2;
            s1 << this->pipeId;
            s2 << other;
            ASSERT_EQ(s1.str(), s2.str());
        }
    };

    printsafe("START MAIN");

    // SETTINGS
    int nThreads{5};
    const int N_OPS{1000};
    const int N_EVTS{2550};
    const std::string inputString{"asdfgh"};

    static std::map<std::thread::id, int> threadMap;

    int inputInt{0};
    for (auto c : inputString)
    {
        inputInt += int(c);
    }
    int expectedProcessed{N_OPS + inputInt};

    // Fake ProtocolHandler + Enviroment + Router
    rxcpp::subjects::subject<std::string> pipeline;
    auto pipelineIn = pipeline.get_subscriber();

    std::atomic<int> total{0};
    auto pipeBuilder = [&total, &N_OPS, &N_EVTS,
                        expectedProcessed](rxcpp::observable<std::string> input) -> rxcpp::composite_subscription
    {
        printsafe("PipeBuilder builds");

        auto mapFunctionAddOnce = [](std::string e)
        {
            event evt;
            int sum = 0;
            for (char c : e)
            {
                sum += int(c);
            }
            evt.pipeId = std::this_thread::get_id();
            evt.e = sum;
            return evt;
        };
        rxcpp::observable<event> innerPipe = input | map(mapFunctionAddOnce);

        auto mapFunctionAddMany = [](event e) -> event
        {
            e.check(std::this_thread::get_id());
            e.e += 1;
            return e;
        };
        for (auto i = 0; i < N_OPS; ++i)
        {
            innerPipe = innerPipe | map(mapFunctionAddMany);
        }

        return innerPipe.subscribe(
            [&total, expectedProcessed](event e)
            {
                ++total;
                printsafe("Pipeline processed(" + std::to_string(e.e) + ") iter: " + std::to_string(total));
                threadMap[std::this_thread::get_id()]++;

                ASSERT_EQ(e.pipeId, std::this_thread::get_id());
            },
            [](auto eptr)
            {
                printsafe("Pipeline got error: " + rxcpp::util::what(eptr));
                FAIL();
            },
            [&total, &N_EVTS]()
            {
                printsafe("Pipeline completed: " + std::to_string(total));
                ASSERT_EQ(total, N_EVTS);
            });
    };

    auto pipelineSubscription = pipeBuilder(pipeline.get_observable());

    // Fake Server | input
    auto fakeServer = rxcpp::observable<>::create<rxcpp::observable<std::string>>(
        [&inputString](auto s)
        {
            for (auto i = 0; i < N_EVTS; ++i)
            {
                s.on_next(rxcpp::observable<>::just<std::string>(inputString));
            }
            printsafe("Producer completed");
            s.on_completed();
        });

    auto threadFactory = [](auto f)
    {
        auto t = std::thread{f};
        threadMap[t.get_id()] = 0;
        return t;
    };
    auto sc = rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads, threadFactory);
    static auto scW = rxcpp::observe_on_one_worker(sc);

    std::atomic<int> eventsCounted{0};

    fakeServer.subscribe(
        [pipelineIn, &eventsCounted](rxcpp::observable<std::string> o)
        {
            ++eventsCounted;
            o.observe_on(scW).subscribe([pipelineIn](auto event) { pipelineIn.on_next(event); },
                                        [](auto eptr) { printsafe("inner got error: " + rxcpp::util::what(eptr)); },
                                        []() {});
        },
        [pipelineIn](auto eptr)
        {
            printsafe("Control subscriber got error: " + rxcpp::util::what(eptr));
            pipelineIn.on_error(eptr);
            // TODO: is the following message a TODO?
            // wait until is unsubscribed
        },
        [&N_EVTS, &eventsCounted]()
        {
            printsafe("Control subscriber completed: " + std::to_string(eventsCounted));

            // TODO: is the following message a TODO?
            // wait until is unsubscribed
            ASSERT_EQ(N_EVTS, eventsCounted);
        });

    while (total != N_EVTS)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    pipelineIn.on_completed();

    for (auto thread : threadMap)
    {
        ASSERT_EQ(N_EVTS / nThreads, thread.second);
    }

    printsafe("END MAIN");
}
