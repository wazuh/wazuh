#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <algorithm>
#include <vector>

#include "json.hpp"
#include "rapidjson/document.h"
#include "rapidjson/pointer.h"

#include "builder.hpp"
#include "registry.hpp"

#define GTEST_COUT std::cout << "[          ] [ INFO ] "


using namespace std;
using namespace rxcpp;
using Value = rapidjson::Value;
using event = json::Document;

// entry_point as observable
event generate()
{
    auto t = std::time(nullptr);
    auto tm = *std::gmtime(&t);

    std::string cstr(30, '\0');
    auto len = std::strftime(&cstr[0], cstr.size(), "%FT%TZ%z", &tm);
    cstr.erase(len, std::string::npos);
    auto message = R"({
        "event": {
            "original": "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"
        },
        "wazuh": {
            "agent": {
                "id": "001",
                "name": "agentSim",
                "version": "PoC"
            },
            "event": {
                "format": "text",
                "id": "9aa69e7b-e1b0-530e-a710-49108e86019b",
                "ingested": "2021-10-26T16:50:34.348945Z",
                "kind": "event"
            },
            "host": {
                "architecture": "x86_64",
                "hostname": "hive",
                "ip": "127.0.1.1",
                "mac": "B0:7D:64:11:B3:13",
                "os": {
                    "kernel": "5.14.14-arch1-1",
                    "name": "Linux",
                    "type": "posix",
                    "version": "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"
                }
            },
            "module", {
                {"name", "logtest"},
                {"source", "apache"},
                {"maptest", "unchanged"},
            }
        }
    })";
    return event(message);
}

event generate_with_missing_field()
{
    auto t = std::time(nullptr);
    auto tm = *std::gmtime(&t);

    std::string cstr(30, '\0');
    auto len = std::strftime(&cstr[0], cstr.size(), "%FT%TZ%z", &tm);
    cstr.erase(len, std::string::npos);
    auto message = R"({
        "event": {
            "original": "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"
        },
        "wazuh": {
            "agent": {
                "id": "001",
                "name": "agentSim",
                "version": "PoC"
            },
            "event": {
                "format": "text",
                "id": "9aa69e7b-e1b0-530e-a710-49108e86019b",
                "ingested": "2021-10-26T16:50:34.348945Z",
                "kind": "event"
            },
            "host": {
                "architecture": "x86_64",
                "hostname": "hive",
                "ip": "127.0.1.1",
                "mac": "B0:7D:64:11:B3:13",
                "os": {
                    "kernel": "5.14.14-arch1-1",
                    "name": "Linux",
                    "type": "posix",
                    "version": "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"
                }
            },
            "module", {
                {"name", "logtest"},
                {"source", "apache"},
            }
        }
    })";

    return event(message);
}

auto handler = [](rxcpp::subscriber<event> s)
{
    s.on_next(generate());
    s.on_next(generate_with_missing_field());
    s.on_completed();
};

TEST(MapValueTest, Initializes)
{
    // Get registry instance as all builders are only accesible by it
    builder::internals::Registry& registry = builder::internals::Registry::instance();

    // Retreive builder
    ASSERT_NO_THROW(auto builder = builder::internals::Registry::instance().builder<observable<json::Document>(observable<json::Document>,
                                       rapidjson::Value)>("map.value"));
}
/*
TEST(MapValueTest, Builds)
{
    // Get registry instance as all builders are only accesible by it
    builder::internals::Registry& registry = builder::internals::Registry::instance();

    // Fake entry poing
    auto entry_point = rxcpp::observable<>::create<json>(handler);

    // Retreive builder
    auto _builder = (const builder::internals::JsonBuilder*)(registry.get_builder("map.value"));

    // Build
    ASSERT_NO_THROW(auto _observable = _builder->build(entry_point, json({{"field", "value"}})));

    // Error not json object
    ASSERT_THROW(auto _observable = _builder->build(entry_point, json({"field", "value"})), builder::internals::BuildError);

    // Error more than one key
    ASSERT_THROW(auto _observable = _builder->build(entry_point, json({{"field", "value"}, {"error", "value"}})), builder::internals::BuildError);
}

TEST(MapValueTest, Operates)
{
    // Get registry instance as all builders are only accesible by it
    builder::internals::Registry& registry = builder::internals::Registry::instance();

    // Fake entry poing
    rxcpp::observable<json> entry_point = rxcpp::observable<>::create<json>(handler);

    // Retreive builder
    auto _builder = static_cast<const builder::internals::JsonBuilder*>(registry.get_builder("map.value"));

    // Build
    auto _observable = _builder->build(entry_point, json({{"module.maptest", "changed"}}));

    // Fake subscriber
    vector<json> observed;
    auto on_next = [&observed](json j)
    {
        observed.push_back(j);
    };
    auto on_complete = []() {};
    auto subscriber = rxcpp::make_subscriber<json>(on_next, on_complete);

    // Operate
    ASSERT_NO_THROW(_observable.subscribe(subscriber));
    ASSERT_EQ(observed.size(), 2);
    for_each(begin(observed), end(observed), [](json j)
    {
        ASSERT_EQ(j["module"]["maptest"], json("changed"));
    });
}
*/