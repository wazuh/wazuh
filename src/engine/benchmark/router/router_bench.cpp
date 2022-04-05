#include <iostream>
#include <string>
#include <algorithm>
#include <chrono>
#include <thread>
#include "benchmark/benchmark.h"
#include "rxcpp/rx.hpp"
#include "nlohmann/json.hpp"
#include "router/router.hpp"
#include "rapidjson/document.h"

using json = nlohmann::ordered_json;


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


class RapidEvent {
private:

public:
    rapidjson::Document doc;
    RapidEvent() {};
    RapidEvent(const RapidEvent& e) {
        rapidjson::Document::AllocatorType& a = doc.GetAllocator();
        doc.CopyFrom(e.doc, a);
    }
};


auto size = 1;

std::shared_ptr<RapidEvent> rgen() {

    auto e = RapidEvent();
    e.doc.Parse(message);

    return std::make_shared<RapidEvent>(e);
}

std::shared_ptr<json> jgen() {
    auto j = json::parse(message);
    return std::make_shared<json>(j);
}



static void rxcpp_bench_filter_rapidevent(benchmark::State& state) {
    auto msg = rgen();

    rxcpp::observable<>::create<std::shared_ptr<RapidEvent>>([&state, msg](rxcpp::subscriber<std::shared_ptr<RapidEvent>> s) {
        for (auto _ : state) {
            s.on_next(msg);
        }
        s.on_completed();
    }).filter([](const std::shared_ptr<RapidEvent> j) {
        auto module = j->doc.FindMember("wazuh")->value.FindMember("module")->value.FindMember("name")->value.GetString();
        return module == "logcollector";
    }).subscribe([](const std::shared_ptr<RapidEvent> j) {

    },
    [&state]() {
        state.SetBytesProcessed(int64_t(state.iterations()) * size);
    });

}

BENCHMARK(rxcpp_bench_filter_rapidevent);


static void rxcpp_bench_filter_shared(benchmark::State& state) {
    auto msg = jgen();

    rxcpp::observable<>::create<std::shared_ptr<json>>([&state, msg](rxcpp::subscriber<std::shared_ptr<json>> s) {
        for (auto _ : state) {
            s.on_next(msg);
        }
        s.on_completed();
    }).filter([](const std::shared_ptr<json> j) {
        return j->at("wazuh").at("module").at("name") == "logcollector";
    }).subscribe([](const std::shared_ptr<json> j) {

    },
    [&state]() {
        state.SetBytesProcessed(int64_t(state.iterations()) * size);
    });

}

BENCHMARK(rxcpp_bench_filter_shared);

static void json_access_compare(benchmark::State& state)
{
    auto msg = jgen();
    for( auto _ : state) {
        msg->at("wazuh").at("module").at("name") == "logcollector";
    }
}

BENCHMARK(json_access_compare);

static void json_access(benchmark::State& state)
{
    auto msg = jgen();
    for( auto _ : state) {
        msg->at("wazuh").at("module").at("name");
    }
}

BENCHMARK(json_access);

static void rapidjson_access(benchmark::State& state)
{
    auto msg = rgen();
    for( auto _ : state) {
        auto v = msg->doc.FindMember("wazuh")->value.FindMember("module")->value.FindMember("name")->value.GetString();
    }
}

BENCHMARK(rapidjson_access);
