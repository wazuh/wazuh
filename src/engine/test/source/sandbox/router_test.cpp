/**
 * @brief Router Test Suite
 */
#include <iostream>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <nlohmann/json.hpp>
#include "router_test.hpp"

using json = nlohmann::json;

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

// Util to generate a json, with the current date
// as the wazuh.event.ingested value.
json JSONGenerator(int id, std::string name, std::string source)
{

    auto t = std::time(nullptr);
    auto tm = *std::gmtime(&t);

    std::string cstr(30, '\0');
    auto len = std::strftime(&cstr[0], cstr.size(), "%FT%TZ%z", &tm);
    cstr.erase(len, std::string::npos);

    return json {
        {   "event", {
                {"original", "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"},
            }
        },
        {   "wazuh", {
                {   "agent", {
                        {"id", "001"},
                        {"name", "agentSim"},
                        {"version", "PoC"},
                    }
                },
                {   "event", {
                        {"format", "text"},
                        {"id", id},
                        {"ingested", cstr },
                        {"kind", "event"},
                    }
                },
                {   "host", {
                        {"architecture", "x86_64"},
                        {"hostname", "hive"},
                        {"ip", "127.0.1.1"},
                        {"mac", "B0:7D:64:11:B3:13"},
                        {   "os",
                            {
                                {"kernel", "5.14.14-arch1-1"},
                                {"name", "Linux"},
                                {"type", "posix"},
                                {"version", "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"},
                            }
                        },
                    }
                },
            }
        },
        {   "module", {
                {"name", name},
                {"source", source},
            }
        }
    };

}


TEST(RoutertTest, RouteEventFromServer)
{

    // Create a protocol handler instance, it will generate n events
    // when run(int n) method is called.
    auto fph = new FakeProtocolHandler<json>(
    [](int i) {
        return JSONGenerator(i, "logcollector", "apache-access");
    });

    // The protocol handler will emit events, each time it has an event
    // to emit, it will call a function on_message, which will receive
    // as a parameter when configured.
    //
    // To integrate the protocol handler with our observer, we link
    // the two callbacks into our handler.
    //
    auto handler = [&,fph](rxcpp::subscriber<json> s) {
        fph->on_message = [&,s](const json j) {
            s.on_next(j);
        };

        fph->on_close = [&,s]() {
            s.on_completed();
        };
    };

    // The way a subscriber is called, is managed by a coordinator
    // There could be multiple coordinators, for example:
    // auto eventloop = rxcpp::observe_on_event_loop();

    // We will create an observable used by the router to deliver
    // the message to the appropriate environment. All messages are
    // dispatched to all subscriber. Each subscriber is responsible
    // to accept it or to discard it as appropriate.
    auto routerObs = rxcpp::observable<>::create<json>(handler).publish().ref_count();

    // This observable will have filters which will be defined
    // by the environment creation. The builder might generate a general
    // environment, but the user might want to route only selected messages.

    // Create a filter which checks whether the json events comes
    // from logcollector
    auto fromLogCollector = [](const json j) {
        return j["module"]["name"] == "logcollector";
    };

    // Create a filter which checks whether the event is an
    // apache-access source
    auto isApacheAccess = [](const json j) {
        return j["module"]["source"] == "apache-access";
    };

    // Create filtered versions of the router
    auto filteredModule = routerObs.filter(fromLogCollector);
    auto filteredSource = routerObs.filter(isApacheAccess);

    int a = 0;
    int b = 0;

    // Each environment is a subscriber which will subscribe
    // to its filtered stream.
    auto envA = rxcpp::make_subscriber<json>(
    [&a](const json j) {
        ++a;
    },
    [&a]() {
        GTEST_COUT << "Environment A Got " << a << std::endl;
    });

    auto envB = rxcpp::make_subscriber<json>(
    [&b](const json j) {
        ++b;
    },
    [&b]() {
        GTEST_COUT << "Environment B Got " << b << std::endl;
    });

    // Router connect a filtered router with an environment, by subscribing it
    //
    // beware of subscribe_on vs observe_on semantics!
    filteredModule.subscribe(envA);
    filteredSource.subscribe(envB);

    auto w = fph->run(10);

    std::chrono::milliseconds span (5000);
    while (w.wait_for(span)==std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(a, 10);
    ASSERT_EQ(b, 10);

}


TEST(RouterTest, ObservableTest)
{
    // To make an observable, we need to pass a function
    // to the create method which will receive a subscriber
    // which exposes two methods: on_next and on_complete.
    // This callback will call on_next on event received
    // and on_complete when the processing of all events is
    // done.
    //
    // Cold observable

    // handler is a function which will receive a subscriber to
    // which we will send multiple events
    auto handler = [](rxcpp::subscriber<json> s) {
        s.on_next(JSONGenerator(1,"logcollector","apache-access"));
        s.on_next(JSONGenerator(2, "logcollector","apache-error"));
        s.on_next(JSONGenerator(3, "logcollector","apache-access"));
        s.on_next(JSONGenerator(4, "logcollector","apache-error"));
        s.on_completed();
    };

    // We create an observable which will invoke then handler with
    // the arriving subscribers
    auto values = rxcpp::observable<>::create<json>(handler);

    // Create a subscriber for json items, which is a class
    // which has two methods: on_next, and on_complete.
    // Every time a new event from the observable is generated
    // the subscriber on_next method is called.
    // When there are no more events, the method on_complete is called
    //

    // Create a on_next() function which will receive json
    // type events
    auto on_next =     [](json j) {
        GTEST_COUT << "Got an event" << std::endl;
    };

    // Create an on_complete function whjich will do the necessary
    // clean up and signal the end
    auto on_complete = []() {
        GTEST_COUT <<  "Completed" << std::endl;
    };

    // Create the subscriber
    auto subscriber = rxcpp::make_subscriber<json>(on_next, on_complete);

    // Start listening to events by subscribing a subscriber.

    // The way a subscriber is called, is managed by a coordinator
    // There could be multiple coordinators, for example:
    // auto eventloop = rxcpp::observe_on_event_loop();

    // We can use the coordinator using the operator subscribe_on
    // and the, finally, subscribing to the coordinator.
    values.subscribe(subscriber);

}