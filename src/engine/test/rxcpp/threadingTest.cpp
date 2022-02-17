/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <chrono>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <testUtils.hpp>
#include <thread>

// TEST(RxcppThreading, ObserveOnExample)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     auto values = rxcpp::observable<>::range(1, 3).map(
//         [](int v)
//         {
//             GTEST_COUT << "[thread " << std::_thread::get_id() << "] Emit value " << v << endl;
//             return v;
//         });

//     values.observe_on(rxcpp::synchronize_new_thread())
//         .as_blocking()
//         .subscribe([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl;
//         },
//                    []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });
//     values.observe_on(rxcpp::synchronize_new_thread())
//         .as_blocking()
//         .subscribe([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl;
//         },
//                    []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, SubscribeOnExample)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     auto values = rxcpp::observable<>::range(1, 3).map(
//         [](int v)
//         {
//             GTEST_COUT << "[thread " << std::_thread::get_id() << "] Emit value " << v << endl;
//             return v;
//         });
//     values.subscribe_on(rxcpp::synchronize_new_thread())
//         .as_blocking()
//         .subscribe([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl;
//         },
//                    []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, MultipleObserveOnExample)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     rxcpp::subjects::subject<int> subj;
//     auto values = subj.get_observable();
//     values.observe_on(rxcpp::synchronize_new_thread())
//         .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl; })
//         .observe_on(rxcpp::synchronize_new_thread())
//         .subscribe([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl;
//         },
//                    []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     auto input = subj.get_subscriber();
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 1" << endl;
//     input.on_next(1);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 2" << endl;
//     input.on_next(2);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 3" << endl;
//     input.on_next(3);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, ObserveOnAfterMultipleOpExample)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     rxcpp::subjects::subject<int> subj;
//     auto values = subj.get_observable();
//     values.tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] Tap1OnNext: " << v << endl;
//     })
//         .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] Tap2OnNext: " << v << endl; })
//         .observe_on(rxcpp::synchronize_new_thread())
//         .subscribe([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl;
//         },
//                    []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     auto input = subj.get_subscriber();
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 1" << endl;
//     input.on_next(1);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 2" << endl;
//     input.on_next(2);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 3" << endl;
//     input.on_next(3);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, SubscribeOnAfterMultipleOpExample)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     rxcpp::subjects::subject<int> subj;
//     auto values = subj.get_observable();
//     values.tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] Tap1OnNext: " << v << endl;
//     })
//         .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] Tap2OnNext: " << v << endl; })
//         .map(
//             [](int v)
//             {
//                 GTEST_COUT << "[thread " << std::_thread::get_id() << "] MapOnNext: " << v << endl;
//                 return v;
//             })
//         .subscribe_on(rxcpp::synchronize_new_thread())
//         .subscribe([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl;
//         },
//                    []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     auto input = subj.get_subscriber();
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 1" << endl;
//     input.on_next(1);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 2" << endl;
//     input.on_next(2);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 3" << endl;
//     input.on_next(3);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, SimpleRoundRobin)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;

//     struct rrState
//     {
//         size_t size;
//         size_t current;
//         size_t next()
//         {
//             auto ret = current;
//             ++current;
//             current = current == size ? 0 : current;
//             return ret;
//         }
//         rrState(size_t size) : size{size}, current{0}
//         {
//         }
//     };

//     rxcpp::subjects::subject<int> subj1, subj2, subj3;
//     auto th1 =
//         subj1.get_observable()
//             .observe_on(rxcpp::synchronize_new_thread())
//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             }) .subscribe([](int v)
//                        { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//                        []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     auto th2 =
//         subj2.get_observable()
//             .observe_on(rxcpp::synchronize_new_thread())
//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             }) .subscribe([](int v)
//                        { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//                        []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     auto th3 =
//         subj3.get_observable()
//             .observe_on(rxcpp::synchronize_new_thread())
//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             }) .subscribe([](int v)
//                        { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//                        []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     vector<rxcpp::subscriber<int>> inputs{subj1.get_subscriber(), subj2.get_subscriber(), subj3.get_subscriber()};
//     rrState sc(3);
//     for (auto i = 0; i < 6; ++i)
//     {
//         auto j = sc.next();
//         GTEST_COUT << "[thread " << std::_thread::get_id() << "]"
//                    << "[" << j << "]Produces " << i << endl;
//         inputs[j].on_next(i);
//         std::_thread::sleep_for(chrono::milliseconds(10));
//     }

//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Remove Add thread (2)" << endl;
//     th3.unsubscribe();
//     th3 =
//         subj3.get_observable()
//             .observe_on(rxcpp::synchronize_new_thread())
//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             }) .subscribe([](int v)
//                        { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//                        []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     for (auto i = 0; i < 6; ++i)
//     {
//         auto j = sc.next();
//         GTEST_COUT << "[thread " << std::_thread::get_id() << "]"
//                    << "[" << j << "]Produces " << i << endl;
//         inputs[j].on_next(i);
//         std::_thread::sleep_for(chrono::milliseconds(10));
//     }
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Add thread (3)" << endl;
//     rxcpp::subjects::subject<int> subj4;
//     auto th4 =
//         subj4.get_observable()
//             .observe_on(rxcpp::synchronize_new_thread())

//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             }) .subscribe([](int v)
//                        { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//                        []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });
//     inputs.push_back(subj4.get_subscriber());
//     sc.size = 4;
//     for (auto i = 0; i < 6; ++i)
//     {
//         auto j = sc.next();
//         GTEST_COUT << "[thread " << std::_thread::get_id() << "]"
//                    << "[" << j << "]Produces " << i << endl;
//         inputs[j].on_next(i);
//         std::_thread::sleep_for(chrono::milliseconds(10));
//     }
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, ObserveOnWithMiddleSubject)
// {
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     rxcpp::subjects::subject<int> subj;
//     auto values =
//         subj.get_observable()
//             .observe_on(rxcpp::synchronize_new_thread())
//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             });

//     auto middleSubj = subjects::subject<int>();
//     middleSubj.get_observable().subscribe(
//         [](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//         []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });
//     values.subscribe(middleSubj.get_subscriber());

//     auto input = subj.get_subscriber();
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 1" << endl;
//     input.on_next(1);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 2" << endl;
//     input.on_next(2);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 3" << endl;
//     input.on_next(3);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, ThreadFactory)
// {
//     auto worker = schedulers::worker();
//     auto action = schedulers::make_action(
//         [](schedulers::schedulable) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] Action" << endl;
//         });
//     auto loop = schedulers::make_event_loop(
//         //  lambda is the thread pool factory
//         // f is the task issued by rxcpp
//         [](function<void()> f) -> thread
//         {
//             // Thread pool implementation goes here
//             return thread(f);
//         });

//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Start task" << endl;
//     rxcpp::subjects::subject<int> subj;
//     auto values =
//         subj.get_observable()
//             .observe_on(identity_same_worker(loop.create_worker()))
//             .tap([](int v) { GTEST_COUT << "[thread " << std::_thread::get_id() << "] TapOnNext: " << v << endl;
//             }) .subscribe([](int v)
//                        { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnNext: " << v << endl; },
//                        []() { GTEST_COUT << "[thread " << std::_thread::get_id() << "] OnCompleted" << endl; });

//     auto input = subj.get_subscriber();
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 1" << endl;
//     input.on_next(1);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 2" << endl;
//     input.on_next(2);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Produces 3" << endl;
//     input.on_next(3);
//     std::_thread::sleep_for(chrono::milliseconds(10));
//     GTEST_COUT << "[thread " << std::_thread::get_id() << "] Finish task" << endl;
// }

// TEST(RxcppThreading, CustomScheduler)
// {
//     printsafe("Start task");

//     //---------- Get a Coordination
//     auto coordination = rxcpp::serialize_new_thread();

//     //------- Create a Worker instance through a factory method
//     auto worker = coordination.create_coordinator().get_worker();

//     //--------- Create a action object
//     auto sub_action =
//         rxcpp::schedulers::make_action([](const rxcpp::schedulers::schedulable &) { printsafe("Action executed"); });

//     //------------- Create a schedulable and schedule the action
//     auto scheduled = rxcpp::schedulers::make_schedulable(worker, sub_action);
//     scheduled.schedule();

//     printsafe("Finish task");
// }

// TEST(RxcppThreading, CustomSchedulerSchedule)
// {
//     printsafe("Start task");

//     //-------- Create a Coordination function
//     auto coordination = rxcpp::observe_on_new_thread();
//     //-------- Instantiate a coordinator and create a worker
//     auto worker = coordination.create_coordinator().get_worker();
//     //--------- start and the period
//     auto start = coordination.now() + std::chrono::milliseconds(1);
//     auto period = std::chrono::milliseconds(1);
//     //----------- Create an Observable (Replay )
//     auto values = rxcpp::observable<>::interval(start, period).take(5).replay(2, coordination);
//     //--------------- Subscribe first time using a Worker
//     worker.schedule(
//         [&](const rxcpp::schedulers::schedulable & sc)
//         {
//             printsafe("Worked schedule call");
//             values.subscribe([](long v) { printsafe("1: " + std::to_string(v)); },
//                              []()
//                              {
//                                  // std::_thread::sleep_for(chrono::milliseconds(5000));
//                                  printsafe("1: OnCompletedn");
//                              });
//         });
//     worker.schedule(
//         [&](const rxcpp::schedulers::schedulable &)
//         {
//             printsafe("Worked schedule call");
//             values.subscribe(
//                 [](long v)
//                 {
//                     // std::_thread::sleep_for(chrono::milliseconds(5000));
//                     printsafe("2: " + std::to_string(v));
//                 },
//                 []() { printsafe("2: OnCompletedn"); });
//         });
//     //----- Start the emission of values
//     worker.schedule(
//         [&](const rxcpp::schedulers::schedulable &)
//         {
//             printsafe("Worked connect call");
//             values.connect();
//         });
//     //------- Add blocking subscription to see results
//     values.as_blocking().subscribe();

//     printsafe("Finish task");

//     // We created a hot Observable using the replay mechanism to take care of the late subscription by some
//     Observers.
//     // We also created a Worker to do the scheduling for subscription and to connect the Observers with the
//     Observable.
//     // The previous program demonstrates how the Scheduler works in RxCpp
// }

#include <memory>
#include <uvw/tcp.hpp>
schedulers::run_loop rl;
using obs_t = observable<observable<observable<int>>>;
using namespace rxcpp::schedulers;

struct event_loopC : public scheduler_interface
{
private:
    typedef event_loopC this_type;
    event_loopC(const this_type &);

    struct loop_worker : public worker_interface
    {
    private:
        typedef loop_worker this_type;
        loop_worker(const this_type &);

        typedef rxcpp::schedulers::detail::schedulable_queue<typename clock_type::time_point> queue_item_time;

        typedef queue_item_time::item_type item_type;

        composite_subscription lifetime;
        worker controller;
        std::shared_ptr<const scheduler_interface> alive;

    public:
        virtual ~loop_worker()
        {
        }
        loop_worker(composite_subscription cs, worker w, std::shared_ptr<const scheduler_interface> alive)
            : lifetime(cs), controller(w), alive(alive)
        {
            auto token = controller.add(cs);
            cs.add([token, w]() { w.remove(token); });
        }

        virtual clock_type::time_point now() const
        {
            return clock_type::now();
        }

        virtual void schedule(const schedulable & scbl) const
        {
            controller.schedule(lifetime, scbl.get_action());
        }

        virtual void schedule(clock_type::time_point when, const schedulable & scbl) const
        {
            controller.schedule(when, lifetime, scbl.get_action());
        }
    };

    mutable thread_factory factory;
    scheduler newthread;
    mutable std::atomic<std::size_t> count;
    composite_subscription loops_lifetime;
    std::vector<worker> loops;

public:
    event_loopC()
        : factory([](std::function<void()> start) { return std::thread(std::move(start)); }),
          newthread(make_new_thread()), count(0)
    {
        auto remaining = 6;

        // auto remaining = std::max(std::thread::hardware_concurrency(), unsigned(4));
        while (remaining--)
        {
            loops.push_back(newthread.create_worker(loops_lifetime));
        }
    }
    explicit event_loopC(thread_factory tf) : factory(tf), newthread(make_new_thread(tf)), count(0)
    {
        // auto remaining = std::max(std::thread::hardware_concurrency(), unsigned(4));
        auto remaining = 6;
        while (remaining--)
        {
            loops.push_back(newthread.create_worker(loops_lifetime));
        }
    }
    virtual ~event_loopC()
    {
        loops_lifetime.unsubscribe();
    }

    virtual clock_type::time_point now() const
    {
        return clock_type::now();
    }

    virtual worker create_worker(composite_subscription cs) const
    {
        return worker(cs, std::make_shared<loop_worker>(cs, loops[++count % loops.size()], this->shared_from_this()));
    }
};

TEST(RxcppThreading, test)
{
    // libuv event_loop
    std::shared_ptr<uvw::Loop> uvloop = uvw::Loop::getDefault();
    std::shared_ptr<uvw::TCPHandle> tcpServer = uvloop->resource<uvw::TCPHandle>();
    const std::string address = std::string{"127.0.0.1"};
    const unsigned int port = 5054;

    // obs_t fakeServer = observable<>::create<observable<observable<int>>>(
    //     [=](subscriber<observable<observable<int>>> s)
    //     {
    //         tcpServer->on<uvw::ListenEvent>(
    //             [address, s](const uvw::ListenEvent &, uvw::TCPHandle & handle)
    //             {
    //                 std::shared_ptr<uvw::TCPHandle> socket = handle.loop().resource<uvw::TCPHandle>();

    //                 s.on_next(observable<>::create<observable<int>>(
    //                     [&socket](subscriber<observable<int>> s)
    //                     {
    //                         socket->on<uvw::DataEvent>(
    //                             [s](const uvw::DataEvent & event, uvw::TCPHandle & client)
    //                             {
    //                                 // here
    //                                 s.on_next(
    //                                     observable::create<int>(
    //                                         [](){

    //                                         }
    //                                     )
    //                                 );
    //                             });
    //                     }));

    //                 handle.accept(*socket);
    //                 socket->read();
    //             });
    //     });

    printsafe("Start task");

    auto mainThread = observe_on_run_loop(rl);
    auto poolThread = observe_on_event_loop();
    int nT = 0;
    auto coord = schedulers::make_scheduler<event_loopC>(
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

    // auto poolCoordintaor = poolThread.create_coordinator();
    vector<observable<int>> events;
    for (auto i = 0; i < 30; ++i)
    {
        events.push_back(observable<>::just<int>(i));
    }

    auto serverFactory = observable<>::iterate(events, mainThread);
    serverFactory.flat_map([&](auto o) { return o.observe_on(identity_same_worker(coord.create_worker())); })
        .subscribe([](auto o) { printsafe("Got event " + to_string(o)); });

    composite_subscription lifetime;

    while (lifetime.is_subscribed())
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
