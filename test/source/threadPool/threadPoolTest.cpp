#include "threadPool.hpp"
#include "MPMCQueue.hpp"
#include <chrono>
#include <future>
#include <gtest/gtest.h>
#include <mutex>
#include <rxcpp/rx-operators.hpp>
#include <rxcpp/rx.hpp>
#include <thread>

namespace Rx
{
using namespace rxcpp;
using namespace rxcpp::subjects;
using namespace rxcpp::schedulers;
namespace rxo = rxcpp::operators;
namespace rxu = rxcpp::util;
} // namespace Rx
using namespace Rx;
using namespace threadpool;
using namespace std;

using namespace std::chrono_literals;

#define GTEST_COUT std::cout << "[   INFO   ] "

static std::mutex m;

void printsafe(std::string s)
{
    m.lock();
    GTEST_COUT << "[thread " << std::this_thread::get_id() << "] " << s << std::endl;
    m.unlock();
}

/**
 * This build a threadpool of 3 threads,
 * and use the subscribe_on only on the endpoint observable.
 *
 * This leads to the concurrent processing of multiple endpoints,
 * but only one connection of those endpoints will be processed at a time.
 *
 * The connection messages of each connection will always be ordered
 * and only one connection per endpoint will be active at a any point
 * in time.
 *
 *
 */
TEST(ThreadPool, EndPointSubscribeOn)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    // run_loop rl;
    // auto sc = rl.get_scheduler();
    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n)
    {
        return observable<>::create<event>(
            [n](subscriber<event> s)
            {
                for (int i = 0; i < n; i++)
                {
                    s.on_next("raw message -> " + std::to_string(i));
                }
                s.on_completed();
            });
    };

    auto newEndpoint = [&pool, newConnection](int n, int j)
    {
        return observable<>::create<con_t>(
                   [newConnection, n, j](subscriber<con_t> s)
                   {
                       for (int i = 0; i < n; i++)
                       {
                           con_t c = newConnection(j);
                           s.on_next(c);
                       }
                       s.on_completed();
                   })
            .subscribe_on(pool);
    };

    std::vector<ept_t> endpoints{newEndpoint(1, 3), newEndpoint(1, 3)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](ept_t o) { return o.tap([](auto e) { printsafe("ept_t -> con_t "); }); })
                      .flat_map([](con_t o) { return o.tap([](auto e) { printsafe("con_t -> msg"); }); });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

/**
 * This build a threadpool of 3 threads,
 * and use the subscribe_on only on the connection observable.
 *
 * This leads to the concurrent processing of multiple messages of a connection,
 * but only one endpoint will be processed at a time.
 *
 * The connection messages of each connection will always be ordered
 * and only one connection per endpoint will be active at a any point
 * in time.
 *
 *
 */
TEST(ThreadPool, ConnectionSubscribeOn)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n)
    {
        return observable<>::create<event>(
                   [n](subscriber<event> s)
                   {
                       for (int i = 0; i < n; i++)
                       {
                           s.on_next("raw message -> " + std::to_string(i));
                       }
                       s.on_completed();
                   })
            .subscribe_on(pool);
    };

    auto newEndpoint = [&pool, newConnection](int n, int j)
    {
        return observable<>::create<con_t>(
            [newConnection, n, j](subscriber<con_t> s)
            {
                for (int i = 0; i < n; i++)
                {
                    con_t c = newConnection(j);
                    s.on_next(c);
                }
                s.on_completed();
            });
    };

    std::vector<ept_t> endpoints{newEndpoint(3, 1), newEndpoint(3, 1)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](ept_t o) { return o.tap([](auto e) { printsafe("ept_t -> con_t "); }); })
                      .flat_map([](con_t o) { return o.tap([](auto e) { printsafe("con_t -> msg"); }); });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

/**
 * This build a threadpool of 3 threads,
 * and use a coordinator in the ept_t
 * flat_map.
 *
 * Then an operator receives a coordinator, which is a factory for coordinated
 * observables, subscribers and schedulable functions.
 *
 * This will run all the operations inside the flat_map in the same thread.
 *
 */
TEST(ThreadPool, EdnPointFlatMapCoordinator)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n)
    {
        return observable<>::create<event>(
            [n](subscriber<event> s)
            {
                for (int i = 0; i < n; i++)
                {
                    s.on_next("raw message -> " + std::to_string(i));
                }
                s.on_completed();
            });
    };

    auto newEndpoint = [&pool, newConnection](int n, int j)
    {
        return observable<>::create<con_t>(
            [newConnection, n, j](subscriber<con_t> s)
            {
                for (int i = 0; i < n; i++)
                {
                    con_t c = newConnection(j);
                    s.on_next(c);
                }
                s.on_completed();
            });
    };

    std::vector<ept_t> endpoints{newEndpoint(1, 1), newEndpoint(1, 1)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](ept_t o) { return o.tap([](auto e) { printsafe("ept_t -> con_t "); }); }, pool)
                      .flat_map([](con_t o) { return o.tap([](auto e) { printsafe("con_t -> msg"); }); });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

/**
 * This build a threadpool of 3 threads,
 * and use a coordinator in the ept_t
 * flat_map.
 *
 * Then an operator receives a coordinator, which is a factory for coordinated
 * observables, subscribers and schedulable functions.
 *
 * This will run all the operations inside the flat_map in the coordinated
 * scheduler.
 *
 */
TEST(ThreadPool, ConnectionFlatMapCoordinator)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n)
    {
        return observable<>::create<event>(
            [n](subscriber<event> s)
            {
                for (int i = 0; i < n; i++)
                {
                    s.on_next("raw message -> " + std::to_string(i));
                }
                s.on_completed();
            });
    };

    auto newEndpoint = [&pool, newConnection](int n, int j)
    {
        return observable<>::create<con_t>(
            [newConnection, n, j](subscriber<con_t> s)
            {
                for (int i = 0; i < n; i++)
                {
                    con_t c = newConnection(j);
                    s.on_next(c);
                }
                s.on_completed();
            });
    };

    std::vector<ept_t> endpoints{newEndpoint(1, 3), newEndpoint(1, 3)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](ept_t o) { return o.tap([](auto e) { printsafe("ept_t -> con_t "); }); })
                      .flat_map([](con_t o) { return o.tap([](auto e) { printsafe("con_t -> msg"); }); }, pool);

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

/**
 * This build a threadpool of 3 threads,
 * and use a observe_on in the endpoint observable.
 *
 * This will make observers of each endpoint to
 * be scheduled.
 *
 */
TEST(ThreadPool, EndPointObservableObserveOn)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n)
    {
        return observable<>::create<event>(
            [n](subscriber<event> s)
            {
                for (int i = 0; i < n; i++)
                {
                    s.on_next("raw message -> " + std::to_string(i));
                }
                s.on_completed();
            });
    };

    auto newEndpoint = [&pool, newConnection](int n, int j)
    {
        return observable<>::create<con_t>(
                   [newConnection, n, j](subscriber<con_t> s)
                   {
                       for (int i = 0; i < n; i++)
                       {
                           con_t c = newConnection(j);
                           s.on_next(c);
                       }
                       s.on_completed();
                   })
            .observe_on(pool);
    };

    std::vector<ept_t> endpoints{newEndpoint(1, 1), newEndpoint(1, 1)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](ept_t o) { return o.tap([](auto e) { printsafe("ept_t -> con_t "); }); })
                      .flat_map([](con_t o) { return o.tap([](auto e) { printsafe("con_t -> msg"); }); });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

/**
 * This build a threadpool of 3 threads,
 * and use a observe_on in the endpoint observable.
 *
 * This will make events of each connection to
 * be scheduled.
 *
 */
TEST(ThreadPool, ConnectionObservableObserveOn)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n)
    {
        return observable<>::create<event>(
                   [n](subscriber<event> s)
                   {
                       for (int i = 0; i < n; i++)
                       {
                           s.on_next("raw message -> " + std::to_string(i));
                       }
                       s.on_completed();
                   })
            .observe_on(pool);
    };

    auto newEndpoint = [&pool, newConnection](int n, int j)
    {
        return observable<>::create<con_t>(
            [newConnection, n, j](subscriber<con_t> s)
            {
                for (int i = 0; i < n; i++)
                {
                    con_t c = newConnection(j);
                    s.on_next(c);
                }
                s.on_completed();
            });
    };

    std::vector<ept_t> endpoints{newEndpoint(1, 1), newEndpoint(1, 1)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](ept_t o) { return o.tap([](auto e) { printsafe("ept_t -> con_t "); }); })
                      .flat_map([](con_t o) { return o.tap([](auto e) { printsafe("con_t -> msg"); }); });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

/**
 * This build a threadpool of 3 threads,
 * and use the subscribe_on only on the connection observable.
 *
 * Two endpoints with 1000 connection each, and
 * each connection will send 10000 messages.
 *
 */
TEST(ThreadPool, HeavyLoadDoubleSubscribeOn)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    scheduler sc = make_scheduler<ThreadPool>(10);
    observe_on_one_worker pool(sc);

    auto newConnection = [&pool](int n, int end_id, int conn_id)
    {
        return observable<>::create<event>(
                   [=](subscriber<event> s)
                   {
                       for (int i = 0; i < n; i++)
                       {
                           s.on_next("[" + std::to_string(end_id) + "," + std::to_string(conn_id) +
                                     "] raw message -> " + std::to_string(i));
                       }
                       s.on_completed();
                   })
            .subscribe_on(pool);
    };

    auto newEndpoint = [&pool, newConnection](int n, int l, int j)
    {
        return observable<>::create<con_t>(
                   [newConnection, n, l, j](subscriber<con_t> s)
                   {
                       for (int i = 0; i < n; i++)
                       {
                           con_t c = newConnection(j, l, i);
                           s.on_next(c);
                       }
                       s.on_completed();
                   })
            .subscribe_on(pool);
    };

    std::vector<ept_t> endpoints{newEndpoint(10, 0, 10), newEndpoint(10, 1, 10)};

    auto server = observable<>::iterate(endpoints)
                      .flat_map(
                          [](ept_t o)
                          {
                              return o; // .tap([](auto e){ printsafe("ept_t -> con_t "); });
                          })
                      .flat_map(
                          [](con_t o)
                          {
                              return o; // .tap([](auto e){ printsafe("con_t -> msg"); });
                          });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe([](std::string e) { printsafe("subscriber got message " + e); },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

TEST(ThreadPool, test)
{
    using event = std::string;
    using con_t = observable<event>;
    using ept_t = observable<con_t>;

    int N_MSG{5};
    int N_CONN{2};
    int N_END{2};

    scheduler sc = make_scheduler<ThreadPool>(10);
    observe_on_one_worker pool(sc);

    auto make_connection = [=](int endpoint, int connection) -> observable<con_t>
    {
        return observable<>::create<con_t>(
            [=](auto s)
            {
                for (auto i = 0; i < N_MSG; ++i)
                {
                    s.on_next(observable<>::just<std::string>("[" + std::to_string(endpoint) + "," +
                                                              std::to_string(connection) + "," + std::to_string(i) +
                                                              "]"));
                }
                s.on_completed();
            });
    };

    auto make_endpoint = [=](int endpoint) -> observable<ept_t>
    {
        return observable<>::create<ept_t>(
            [=](auto s)
            {
                for (auto i = 0; i < N_CONN; ++i)
                {
                    s.on_next(make_connection(endpoint, i));
                }
                s.on_completed();
            });
    };

    std::vector<observable<ept_t>> endpoints;
    for (auto i = 0; i < N_END; ++i)
    {
        endpoints.push_back(make_endpoint(i));
    }

    auto server = observable<>::iterate(endpoints)
                      .flat_map([](auto o) { return o; })
                      .flat_map([](auto o) { return o; })
                      .flat_map([](auto o) { return o; });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    // server.subscribe(
    //     [](con_t e){
    //         e.subscribe([](std::string e){
    //             printsafe("Got event "+e);
    //         }, [](auto){},[](){});
    //     },
    //     [](std::exception_ptr & e){
    //         printsafe("subscriber error");
    //     },
    //     [&promise](){
    //         printsafe("subscriber completed");
    //         promise.set_value();
    //     }
    // );

    server.subscribe([](std::string e) { std::cerr << "Got event " << e << std::endl; },
                     [](std::exception_ptr & e) { printsafe("subscriber error"); },
                     [&promise]()
                     {
                         printsafe("subscriber completed");
                         promise.set_value();
                     });

    future.get();
}

// TEST(ThreadPool, CoordinatedPulling){
//     printsafe("MAIN THREAD START");
//     scheduler sc = make_scheduler<ThreadPool>(10);
//     observe_on_one_worker pool(sc);
//     int N_THREADS{2};

//     // subjects::synchronize<int, observe_on_one_worker> ts_subject(pool);
//     subjects::subject<int> ts_subject;
//     auto in = ts_subject.get_subscriber();
//     auto out = ts_subject.get_observable().publish();

//     // Dispatching syncronization
//     static condition_variable cv;
//     static mutex cv_m;
//     static atomic_int available_workers{N_THREADS};

//     // Workers
//     auto make_worker = [&](observable<int> input, int id) -> void {
//         input
//             .tap(
//                 [](auto n){
//                     {
//                         std::lock_guard<std::mutex> lk(m);
//                         --available_workers;
//                     }
//                     cv.notify_one();
//                 },
//                 [](auto eptr){},
//                 [](){}
//             )
//             .observe_on(observe_on_new_thread())
//             .map([](auto n){
//                 std::this_thread::sleep_for(std::chrono::milliseconds(200));
//                 return n;
//             })
//             .subscribe([=](int n){
//                 printsafe("[" + std::to_string(id) + "] Sub got: " + std::to_string(n));
//                 {
//                     std::lock_guard<std::mutex> lk(m);
//                     ++available_workers;
//                 }
//                 cv.notify_one();
//             });
//     };

//     for (auto i = 0; i < N_THREADS; ++i){
//         make_worker(out, i);
//     }

//     // Start processing
//     out.connect();
//     int iterations = 30;
//     while (--iterations > 0){
//         {
//             std::unique_lock<std::mutex> lk(cv_m);
//             cv.wait(lk, [](){return available_workers > 0;});
//         }
//         printsafe("Producer sent "+ std::to_string(iterations));
//         in.on_next(iterations);
//     }
//     in.on_completed();

//     std::this_thread::sleep_for(std::chrono::milliseconds(5000));
//     printsafe("MAIN THREAD END");
// }

TEST(ThreadPool, CoordinatedQueuePulling)
{
    printsafe("MAIN THREAD START");
    scheduler sc = make_scheduler<ThreadPool>(10);
    observe_on_one_worker pool(sc);
    int N_THREADS{2};

    // subjects::synchronize<int, observe_on_one_worker> ts_subject(pool);
    subjects::subject<int> ts_subject;
    auto in = ts_subject.get_subscriber();
    auto out = ts_subject.get_observable().publish();

    static rigtorp::MPMCQueue<int> queue(2);
    // Dispatching syncronization
    // static condition_variable cv_w;
    // static condition_variable cv;
    // static mutex cv_m;
    // static const int MAX_CAPACITY{2};
    // static atomic_int queue_size{0};

    // struct Queue{
    //     vector<int> jobs;
    //     void blocking_push(int n){
    //         {
    //             std::unique_lock<std::mutex> lk(cv_m);
    //             cv.wait(lk, [](){return queue_size < MAX_CAPACITY;});
    //         }
    //         jobs.push_back(n);
    //         {
    //             std::lock_guard<std::mutex> lk(m);
    //             ++queue_size;
    //         }
    //         cv_w.notify_one();
    //         cv.notify_one();
    //     }
    //     int blocking_pull(){
    //         {
    //             std::unique_lock<std::mutex> lk(cv_m);
    //             cv.wait(lk, [](){return queue_size > 0;});
    //         }
    //         int ret = jobs.back();
    //         jobs.pop_back();
    //         {
    //             std::lock_guard<std::mutex> lk(m);
    //             --queue_size;
    //         }
    //         cv.notify_one();
    //         return ret;
    //     }
    // }static queue;

    // Workers
    auto make_worker = [&](observable<int> input, int id) -> void
    {
        input
            // .observe_on(observe_on_new_thread())
            .map(
                [](auto n)
                {
                    // std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    return n;
                })
            .subscribe([=](int n) { printsafe("[" + std::to_string(id) + "] Sub got: " + std::to_string(n)); });
    };

    for (auto i = 0; i < N_THREADS; ++i)
    {
        thread t{[i, &make_worker]()
                {
                    subjects::subject<int> in_worker;
                    make_worker(in_worker.get_observable(), i);
                    while (true)
                    {
                       int v;
                       queue.pop(v);
                       in_worker.get_subscriber().on_next(v);
                    }
                }};
        t.detach();
    }

    // Start processing
    out.connect();
    int iterations = 30;
    while (--iterations > 0)
    {
        queue.push(iterations);
        printsafe("Producer sent " + std::to_string(iterations));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    printsafe("MAIN THREAD END");
}

TEST(ThreadPool, CoordinatedQueuePulling2){
    printsafe("MAIN THREAD START");
    static run_loop rl;
    static auto loop = observe_on_run_loop(rl);
    int N_THREADS{3};
    scheduler sc = make_scheduler<ThreadPool>(N_THREADS-1);
    static observe_on_one_worker pool(sc);

    // subjects::synchronize<int, observe_on_one_worker> ts_subject(pool);
    subjects::subject<int> ts_subject;
    auto in = ts_subject.get_subscriber();
    auto out = ts_subject.get_observable().publish();

    static rigtorp::MPMCQueue<int> queue(4);

    // Workers
    auto make_worker_main = [=](observable<int> input, int id) -> void {
        input
            .observe_on(loop)
            .map([](auto n){
                int v;
                bool got = queue.try_pop(v);
                if (got){
                    return v;
                }
                else{
                    return n;
                }
            })
            .filter([](auto v){ return v != -1;})
            .map([](auto n){
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                return n;
            })
            .subscribe([=](int n){
                printsafe("[" + std::to_string(id) + "] Sub got: " + std::to_string(n));
            });
    };
    auto make_worker = [=](observable<int> input, int id) -> void {
        input
            .observe_on(pool)
            .map([](auto n){
                int v;
                bool got = queue.try_pop(v);
                if (got){
                    return v;
                }
                else{
                    return n;
                }
            })
            .filter([](auto v){ return v != -1;})
            .map([](auto n){
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                return n;
            })
            .subscribe([=](int n){
                printsafe("[" + std::to_string(id) + "] Sub got: " + std::to_string(n));
            });
    };

    for (auto i = 0; i < N_THREADS; ++i){
        if (i == 0){
            make_worker_main(out, i);
        }else{
            make_worker(out, i);
        }
    }

    composite_subscription lifetime;
    // Start processing
    int iterations{30};
    out.connect();
    while(lifetime.is_subscribed()) {
        if (iterations > 0){
            if(queue.try_push(iterations)){
                printsafe("Producer sent "+ std::to_string(iterations));
                --iterations;
                in.on_next(-1);
            }else{
                printsafe("WAITING");
            }
        }else{
            lifetime.unsubscribe();
        }

        while (!rl.empty() && rl.peek().when < rl.now()) {
            printsafe("DISPATCHED");
            rl.dispatch();
        }

        in.on_next(-1);

    }
    in.on_completed();

    std::this_thread::sleep_for(std::chrono::milliseconds(5000));
    printsafe("MAIN THREAD END");
}
