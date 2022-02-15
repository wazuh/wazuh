/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <chrono>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <testUtils.hpp>
#include <thread>

TEST(RxcppThreading, ObserveOnExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    auto values = rxcpp::observable<>::range(1, 3).map(
        [](int v)
        {
            GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Emit value " << v << endl;
            return v;
        });


    values.observe_on(rxcpp::synchronize_new_thread())
        .as_blocking()
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    values.observe_on(rxcpp::synchronize_new_thread())
        .as_blocking()
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, SubscribeOnExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    auto values = rxcpp::observable<>::range(1, 3).map(
        [](int v)
        {
            GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Emit value " << v << endl;
            return v;
        });
    values.subscribe_on(rxcpp::synchronize_new_thread())
        .as_blocking()
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, MultipleObserveOnExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values = subj.get_observable();
    values.observe_on(rxcpp::synchronize_new_thread())
        .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
        .observe_on(rxcpp::synchronize_new_thread())
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, ObserveOnAfterMultipleOpExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values = subj.get_observable();
    values.tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap1OnNext: " << v << endl; })
        .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap2OnNext: " << v << endl; })
        .observe_on(rxcpp::synchronize_new_thread())
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, SubscribeOnAfterMultipleOpExample)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto values = subj.get_observable();
    values.tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap1OnNext: " << v << endl; })
        .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Tap2OnNext: " << v << endl; })
        .map(
            [](int v)
            {
                GTEST_COUT << "[thread " << std::this_thread::get_id() << "] MapOnNext: " << v << endl;
                return v;
            })
        .subscribe_on(rxcpp::synchronize_new_thread())
        .subscribe([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                   []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto input = subj.get_subscriber();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 1" << endl;
    input.on_next(1);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 2" << endl;
    input.on_next(2);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Produces 3" << endl;
    input.on_next(3);
    std::this_thread::sleep_for(chrono::milliseconds(10));
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, SimpleRoundRobin)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;

    struct rrState
    {
        size_t size;
        size_t current;
        size_t next()
        {
            auto ret = current;
            ++current;
            current = current == size ? 0 : current;
            return ret;
        }
        rrState(size_t size) : size{size}, current{0}
        {
        }
    };

    rxcpp::subjects::subject<int> subj1, subj2, subj3;
    auto th1 =
        subj1.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto th2 =
        subj2.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    auto th3 =
        subj3.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    vector<rxcpp::subscriber<int>> inputs{subj1.get_subscriber(), subj2.get_subscriber(), subj3.get_subscriber()};
    rrState sc(3);
    for (auto i = 0; i < 6; ++i)
    {
        auto j = sc.next();
        GTEST_COUT << "[thread " << std::this_thread::get_id() << "]"
                   << "[" << j << "]Produces " << i << endl;
        inputs[j].on_next(i);
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }

    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Remove Add thread (2)" << endl;
    th3.unsubscribe();
    th3 =
        subj3.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())
            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });

    for (auto i = 0; i < 6; ++i)
    {
        auto j = sc.next();
        GTEST_COUT << "[thread " << std::this_thread::get_id() << "]"
                   << "[" << j << "]Produces " << i << endl;
        inputs[j].on_next(i);
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Add thread (3)" << endl;
    rxcpp::subjects::subject<int> subj4;
    auto th4 =
        subj4.get_observable()
            .observe_on(rxcpp::synchronize_new_thread())

            .tap([](int v) { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] TapOnNext: " << v << endl; })
            .subscribe([](int v)
                       { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnNext: " << v << endl; },
                       []() { GTEST_COUT << "[thread " << std::this_thread::get_id() << "] OnCompleted" << endl; });
    inputs.push_back(subj4.get_subscriber());
    sc.size = 4;
    for (auto i = 0; i < 6; ++i)
    {
        auto j = sc.next();
        GTEST_COUT << "[thread " << std::this_thread::get_id() << "]"
                   << "[" << j << "]Produces " << i << endl;
        inputs[j].on_next(i);
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}

TEST(RxcppThreading, RxcppEventLoopRoundRobin)
{
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Start task" << endl;
    rxcpp::subjects::subject<int> subj;
    auto input = subj.get_subscriber();

    auto sched = schedulers::make_event_loop();
    auto worker1 = sched.create_worker();
    auto worker11 = sched.create_worker();
    auto worker2 = sched.create_worker();
    auto worker22 = sched.create_worker();

    for (int i = 0; i < 2; ++i)
    {
        observable<>::from(1, 2, 3)
            .observe_on(identity_same_worker(worker1))
            .map(
                [](int v)
                {
                    cout << "map: tid=" << this_thread::get_id() << " v=" << v << endl;
                    return v + 3;
                })

            .subscribe([](int v) { cout << "next: tid=" << this_thread::get_id() << " v=" << v << endl; });
        std::this_thread::sleep_for(chrono::milliseconds(10));
    }

    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] Finish task" << endl;
}
