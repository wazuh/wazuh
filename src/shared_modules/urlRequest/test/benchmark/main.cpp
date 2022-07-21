/*
 * Wazuh urlRequest test component
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#include "httplib.h"
#pragma GCC diagnostic pop

#include "benchmark.h"
#include "curlWrapper.hpp"
#include "HTTPRequest.hpp"
#include <iostream>

class EchoServer
{
    public:
        EchoServer()
        {
            std::thread t([&]()
            {
                httplib::Server server;

                server.Get("/", [](const httplib::Request& /*req*/, httplib::Response& res) {
                    res.set_content("Hello World!", "text/json");
                });

                server.Post("/", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.body, "text/json");
                });

                server.Put("/", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.body, "text/json");
                });

                server.Delete(R"(/(\d+))", [](const httplib::Request& req, httplib::Response& res) {
                    res.set_content(req.matches[1], "text/json");
                });

                server.listen("localhost", 44441);
            });
            t.detach();
        }
};

EchoServer server;

static void BM_Get(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().get(HttpURL("http://localhost:44441/"),
        [&](const std::string &/*result*/)
        { });
    }
}
BENCHMARK(BM_Get);

static void BM_Post(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().post(HttpURL("http://localhost:44441/"),
                                     R"({"foo": "bar"})",
        [&](const std::string &/*result*/)
        { });
    }
}
BENCHMARK(BM_Post);

static void BM_Update(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().update(HttpURL("http://localhost:44441/"),
                                    R"({"foo": "bar"})",
        [&](const std::string &/*result*/)
        { });
    }
}
BENCHMARK(BM_Update);

static void BM_Delete(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().delete_(HttpURL("http://localhost:44441/12345"),
        [&](const std::string &/*result*/)
        { });
    }
}

BENCHMARK(BM_Delete);


static void BM_Download(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().download(HttpURL("http://localhost:44441/"),
        "out.txt",
        [&](const std::string &/*result*/)
        { });
    }
}
BENCHMARK(BM_Download);

BENCHMARK_MAIN();
