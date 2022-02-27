#include <chrono>
#include <mutex>
#include <thread>
#include <future>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <rxcpp/rx-operators.hpp>
#include "threadPool.hpp"

namespace Rx{
    using namespace rxcpp;
    using namespace rxcpp::subjects;
    using namespace rxcpp::schedulers;
    namespace rxo = rxcpp::operators;
    namespace rxu = rxcpp::util;
}
using namespace Rx;
using namespace threadpool;

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
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        });
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        }).subscribe_on(pool);
    };

    std::vector<ept_t> endpoints {newEndpoint(1,3), newEndpoint(1,3) };

    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o.tap([](auto e){ printsafe("ept_t -> con_t "); });
        })
        .flat_map([](con_t o){
            return o.tap([](auto e){ printsafe("con_t -> msg"); });
        });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
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
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        }).subscribe_on(pool);
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        });
    };

    std::vector<ept_t> endpoints {newEndpoint(3,1), newEndpoint(3,1) };



    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o.tap([](auto e){ printsafe("ept_t -> con_t "); });
        })
        .flat_map([](con_t o){
            return o.tap([](auto e){ printsafe("con_t -> msg"); });
        });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
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
    
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        });
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        });
    };

    std::vector<ept_t> endpoints {newEndpoint(1,1), newEndpoint(1,1) };

    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o.tap([](auto e){ printsafe("ept_t -> con_t "); });
        }, pool)
        .flat_map([](con_t o){
            return o.tap([](auto e){ printsafe("con_t -> msg"); });
        });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
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
    
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        });
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        });
    };

    std::vector<ept_t> endpoints {newEndpoint(1,3), newEndpoint(1,3) };

    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o.tap([](auto e){ printsafe("ept_t -> con_t "); });
        })
        .flat_map([](con_t o){
            return o.tap([](auto e){ printsafe("con_t -> msg"); });
        }, pool);

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
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
    
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        });
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        }).observe_on(pool);
    };

    std::vector<ept_t> endpoints {newEndpoint(1,1), newEndpoint(1,1) };

    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o.tap([](auto e){ printsafe("ept_t -> con_t "); });
        })
        .flat_map([](con_t o){
            return o.tap([](auto e){ printsafe("con_t -> msg"); });
        });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
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
    
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        }).observe_on(pool);
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        });
    };

    std::vector<ept_t> endpoints {newEndpoint(1,1), newEndpoint(1,1) };

    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o.tap([](auto e){ printsafe("ept_t -> con_t "); });
        })
        .flat_map([](con_t o){
            return o.tap([](auto e){ printsafe("con_t -> msg"); });
        });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
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


    scheduler sc = make_scheduler<ThreadPool>(3);
    observe_on_one_worker pool(sc); 
    
    auto newConnection = [&pool](int n) {
        return observable<>::create<event>([n](subscriber<event> s){
            for(int i=0;i<n; i++) {
                s.on_next("raw message -> " + std::to_string(i));
            }
            s.on_completed();
        }).subscribe_on(pool);
    };
    
    auto newEndpoint = [&pool, newConnection](int n, int j){
        return observable<>::create<con_t>([newConnection, n, j](subscriber<con_t> s){
            for(int i=0;i<n;i++) {
                con_t c = newConnection(j);
                s.on_next(c);
            }
            s.on_completed();  
        }).subscribe_on(pool);
    };

    std::vector<ept_t> endpoints {newEndpoint(1000,100000), newEndpoint(1000,100000) };



    auto server = observable<>::iterate(endpoints)
        .flat_map([](ept_t o ){ 
            return o; // .tap([](auto e){ printsafe("ept_t -> con_t "); });
        })
        .flat_map([](con_t o){
            return o; // .tap([](auto e){ printsafe("con_t -> msg"); });
        });

    std::promise<void> promise;
    std::future<void> future = promise.get_future();

    server.subscribe(
        [](std::string e){
            // printsafe("subscriber got message "+e);
        },
        [](std::exception_ptr & e){
            printsafe("subscriber error");
        },
        [&promise](){
            printsafe("subscriber completed");
            promise.set_value();
        }
    );
    
    future.get();
}