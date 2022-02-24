/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 *  program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "threadingTest.hpp"

#define WAIT_FOR_WORKERS_TIME_MS 50

TEST(RxcppThreading, testSchedulerCustomFactoryWithPrints)
{
    printsafe("Start task");

    rxcpp::schedulers::run_loop rl;

    atomic<int> events_count = 0;

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
    this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);

    printsafe("End task");
}

TEST(RxcppThreading, testScheduler_1threads_10events)
{
    rxcpp::schedulers::run_loop rl;

    atomic<int> events_count = 0;

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
    this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testScheduler_6threads_60events)
{
    rxcpp::schedulers::run_loop rl;

    atomic<int> events_count = 0;

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
    this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testScheduler_5threads_50events)
{
    rxcpp::schedulers::run_loop rl;

    atomic<int> events_count = 0;

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
    this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testScheduler_15threads_40events)
{
    rxcpp::schedulers::run_loop rl;

    atomic<int> events_count = 0;

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
    this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, testWithFactory)
{
    rxcpp::schedulers::run_loop rl;

    atomic<int> events_count = 0;

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
    this_thread::sleep_for(chrono::milliseconds(WAIT_FOR_WORKERS_TIME_MS));

    ASSERT_EQ(nEvents, events_count);
}

TEST(RxcppThreading, SubscriberSubjectx100000)
{
    struct event
    {
        thread::id pipeId;
        int e;
        void check(thread::id other)
        {
            stringstream s1;
            stringstream s2;
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
    const string inputString{"asdfgh"};

    static std::map<thread::id, int> threadMap;

    int inputInt{0};
    for (auto c : inputString)
    {
        inputInt += int(c);
    }
    int expectedProcessed{N_OPS + inputInt};

    // Fake ProtocolHandler + Enviroment + Router
    rxcpp::subjects::subject<string> pipeline;
    auto pipelineIn = pipeline.get_subscriber();

    atomic<int> total{0};
    auto pipeBuilder = [&total, &N_OPS, &N_EVTS,
                        expectedProcessed](rxcpp::observable<string> input) -> rxcpp::composite_subscription
    {
        printsafe("PipeBuilder builds");

        auto mapFunctionAddOnce = [](string e)
        {
            event evt;
            int sum = 0;
            for (char c : e)
            {
                sum += int(c);
            }
            evt.pipeId = this_thread::get_id();
            evt.e = sum;
            return evt;
        };
        rxcpp::observable<event> innerPipe = input | rxo::map(mapFunctionAddOnce);

        auto mapFunctionAddMany = [](event e) -> event
        {
            e.check(this_thread::get_id());
            e.e += 1;
            return e;
        };
        for (auto i = 0; i < N_OPS; ++i)
        {
            innerPipe = innerPipe | rxo::map(mapFunctionAddMany);
        }

        return innerPipe.subscribe(
            [&total, expectedProcessed](event e)
            {
                ++total;
                printsafe("Pipeline processed(" + to_string(e.e) + ") iter: " + to_string(total));
                threadMap[this_thread::get_id()]++;

                ASSERT_EQ(e.pipeId, this_thread::get_id());
            },
            [](auto eptr)
            {
                printsafe("Pipeline got error: " + rxu::what(eptr));
                FAIL();
            },
            [&total, &N_EVTS]()
            {
                printsafe("Pipeline completed: " + to_string(total));
                ASSERT_EQ(total, N_EVTS);
            });
    };

    auto pipelineSubscription = pipeBuilder(pipeline.get_observable());

    // Fake Server | input
    auto fakeServer = rxcpp::observable<>::create<rxcpp::observable<string>>(
        [&inputString](auto s)
        {
            for (auto i = 0; i < N_EVTS; ++i)
            {
                s.on_next(rxcpp::observable<>::just<string>(inputString));
            }
            printsafe("Producer completed");
            s.on_completed();
        });

    auto threadFactory = [](auto f)
    {
        auto t = thread{f};
        threadMap[t.get_id()] = 0;
        return t;
    };
    auto sc = rxcpp::schedulers::make_scheduler<ThreadPool>(nThreads, threadFactory);
    static auto scW = rxcpp::observe_on_one_worker(sc);

    atomic<int> eventsCounted{0};

    fakeServer.subscribe(
        [pipelineIn, &eventsCounted](rxcpp::observable<string> o)
        {
            ++eventsCounted;
            o.observe_on(scW)
            .subscribe([pipelineIn](auto event) { pipelineIn.on_next(event); },
                                        [](auto eptr) { printsafe("inner got error: " + rxu::what(eptr)); },
                                        []() {});
        },
        [pipelineIn](auto eptr)
        {
            printsafe("Control subscriber got error: " + rxu::what(eptr));
            pipelineIn.on_error(eptr);
            // TODO: is the following message a TODO?
            // wait until is unsubscribed
        },
        [&N_EVTS, &eventsCounted]()
        {
            printsafe("Control subscriber completed: " + to_string(eventsCounted));

            // TODO: is the following message a TODO?
            // wait until is unsubscribed
            ASSERT_EQ(N_EVTS, eventsCounted);
        });

    while (total != N_EVTS)
    {
        this_thread::sleep_for(chrono::milliseconds(50));
    }

    pipelineIn.on_completed();

    for (auto thread : threadMap)
    {
        ASSERT_EQ(N_EVTS / nThreads, thread.second);
    }

    printsafe("END MAIN");
}

TEST(RxcppThreading, ThreadContinuity)
{
    printsafe("MAIN THREAD START");
    // Event processed by environments
    struct event
    {
        int e;
        thread::id id;
        int conn;
        // Needed to assert all operations are processed on the same thread
        void check(thread::id other)
        {
            if ( id != other) {
                stringstream s1;
                stringstream s2;
                s1 << this->id;
                s2 << other;
                ASSERT_EQ(s1.str(), s2.str());
            };
        }
        event(int i, thread::id id, int conn): e(i), id(id), conn{conn} {}
    };

    using evt_t = observable<event>;
    //using con_t = rxcpp::connectable_observable<evt_t>;
    using con_t = observable<evt_t>;
    using ept_t = observable<con_t>;

    // Settings
    const int n_connections{3};
    const int n_events{10};
    const int n_threads{10};
    const int n_ops = 10;
    const string input_string{"raw"};
    const int input_string_int = [](string s){
        int sum = 0;
        for (char c : s){
            sum+=int(c);
        }
        return sum;
    }(input_string);
    const static auto rand_op_sleep = [](){
        return chrono::milliseconds(rand() % 500);
    };
    const static auto rand_conn_sleep = [](){
        return chrono::milliseconds(rand() % 500);
    };

    // Control Variables
    static mutex m;
    static condition_variable cv;
    const static int total_events{n_events * n_connections};
    ASSERT_EQ(total_events%n_threads, 0);
    const static int events_per_thread{total_events/n_threads};
    static atomic<int> pending_events{total_events};
    static int expected_proccesed{n_ops + input_string_int};
    static std::map<thread::id, int> threads;


    // Scheduler
    auto thread_factory = [](auto f){
        thread t{f};
        threads[t.get_id()] = 0;
        return t;
    };
    auto scEnv = make_scheduler<ThreadPool>(n_threads, thread_factory);
    static auto poolEnv = observe_on_one_worker(scEnv);

    // auto scSrv = make_scheduler<ThreadPool>(2);
    // static auto poolSrv = observe_on_one_worker(scSrv);


    // Connection maker
    auto make_connection = [=](int conn_n) -> con_t {
        // Fake endpoint connection
        return observable<>::create<evt_t>([=](subscriber<evt_t> s){
            for(auto i=0; i < n_events; i++) {
                evt_t e = observable<>::just<string>(input_string)
                    .observe_on(poolEnv)
                    .map([conn_n](string s)-> event {
                        // Fake ProtocolHandler
                        printsafe("Started processing event from connection " + to_string(conn_n));
                        threads[this_thread::get_id()]++;
                        int sum = 0;
                        for (char c : s){
                            sum+=int(c);
                        }
                        return event(sum, this_thread::get_id(), conn_n);
                    });
                //printsafe("Conn sends event "+to_string(i));
                // Simulate variable sending times
                this_thread::sleep_for(rand_conn_sleep());
                s.on_next(e);
            }
            printsafe("Connection "+to_string(conn_n)+" completed");
            s.on_completed();
        });
    };

    // Fake endpoint, creates connections
    ept_t endpoint = observable<>::create<con_t>([=](subscriber<con_t> s){
        printsafe("Endpoint created");
        for(int i=0; i < n_connections; i++) {
            printsafe("Endpopint sends connection "+to_string(i));
            s.on_next(make_connection(i));
        }
        printsafe("Endpoint completed");
        s.on_completed();
    });
    vector<ept_t> endpoints{endpoint};

    // Fake server
    auto server = observable<>::iterate(endpoints).flat_map([](ept_t o){
        printsafe("Server received endpoint");
        return o;
    }).flat_map([](con_t o){
        printsafe("Server received connection");
        return o;
    });

    // Fake enviroment builder
    auto env_builder = [](evt_t in_o) -> evt_t {
        printsafe("Enviroment built");
        auto out_o = in_o;
        for(auto i = 0; i < n_ops; ++i) {
            out_o = out_o
                .map([](event e){
                    // printsafe("Environment map operation" + to_string(e.e));
                    e.check(this_thread::get_id());
                    // Simulate different pipelines
                    this_thread::sleep_for(rand_op_sleep());
                    return event(e.e+1, e.id, e.conn);
                });
        }

        // Fake Output
        out_o.subscribe(
            [](event e){
                //printsafe("Enviroment Output got: "+to_string(e.e));
                e.check(this_thread::get_id());
                ASSERT_EQ(expected_proccesed, e.e);
                pending_events--;
                {
                    unique_lock<mutex> lock(m);
                    cv.notify_one();
                }
            },
            [](auto eptr){
                printsafe("Enviroment Output got error: " + rxu::what(eptr));
            },
            [](){
                printsafe("Enviroment Output competed");
            });

        // Return last graph observable before outputs [unused]
        return out_o;
    };

    // Fake Router --> Add route
    auto router_subj = subjects::subject<event>();
    auto router_in = router_subj.get_subscriber();

    router_subj.get_observable()
        | rxo::filter([](event e){
            //printsafe("Environment filter operation evt id " + to_string(e.e));
            e.check(this_thread::get_id());
            return true;
        })
        | env_builder;

    // Fake main
    server.subscribe(
        [=](evt_t o){
            o.subscribe(
                [=](event e){
                    printsafe("Server subscriber operation got event from connection " + to_string(e.conn));
                    router_in.on_next(e);
                },
                [=](auto eptr){
                    // printsafe("Server subscriber on_error");
                    router_in.on_error(eptr);
                },
                [=](){
                    // printsafe("Server tap subscriber completed");
                }
            );
        },
        [](auto eptr){

        },
        [](){}
    );

    // Scope this so lock is liberated
    {
        unique_lock<mutex> lock(m);
        cv.wait(lock, [&](){ return pending_events == 0; });
    }

    for (const auto p : threads){
        ASSERT_EQ(p.second, events_per_thread);
    }

    // Free enviroment
    router_in.on_completed();
    printsafe("MAIN THREAD END");
}
