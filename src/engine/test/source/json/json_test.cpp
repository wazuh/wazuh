#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "json.hpp"
#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rxcpp/rx-test.hpp"
#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

#define EVENT std::shared_ptr<Event>

using namespace std;
using Value = rapidjson::Value;

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
        "module": {
            "name": "logcollector",
            "source": "apache-access"
        }
    }
})";

TEST(JsonTest, Initialize) {

    ASSERT_NO_THROW(Json::Document default_event());

    ASSERT_NO_THROW(Json::Document json_event(message));

    Json::Document json_event(message);

    ASSERT_NO_THROW(Json::Document copy_event(json_event));

    ASSERT_NO_THROW(Json::Document value_event(*(json_event.get(""))));
    
}

TEST(JsonTest, Operates) {

    Json::Document e(message);

    //Testing set and get
    e.set(".module.name",Value("changed"));

    ASSERT_EQ(*(e.get(".module.name")), Value("changed"));

    ASSERT_TRUE(e.check(".module.name", Value("changed")));

    ASSERT_TRUE(e.check(".module.name"));

}