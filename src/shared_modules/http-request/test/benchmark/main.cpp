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

#include "HTTPRequest.hpp"
#include "benchmark.h"
#include <iostream>

/**
 * @brief This class is a simple HTTP server that provides a simple interface to perform HTTP requests.
 */
namespace
{
class FakeServer final
{
private:
    httplib::Server m_server;
    std::thread m_thread;

public:
    FakeServer()
        : m_thread(&FakeServer::run, this)
    {
        // Wait until server is ready
        while (!m_server.is_running())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    ~FakeServer()
    {
        m_server.stop();
        m_thread.join();
    }

    /**
     * @brief This method is used to start the server.
     */
    void run()
    {
        m_server.Get("/",
                     [](const httplib::Request& /*req*/, httplib::Response& res)
                     { res.set_content("Hello World!", "text/json"); });

        m_server.Post(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Put(
            "/", [](const httplib::Request& req, httplib::Response& res) { res.set_content(req.body, "text/json"); });

        m_server.Delete(R"(/(\d+))",
                        [](const httplib::Request& req, httplib::Response& res)
                        { res.set_content(req.matches[1], "text/json"); });

        m_server.set_keep_alive_max_count(1);
        m_server.listen("localhost", 44441);
    }
};
} // namespace

FakeServer g_server;

/**
 * @brief This function is a benchmark test for the HTTP GET request.
 *
 * @param state Benchmark state.
 */
static void BM_Get(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().get(HttpURL("http://localhost:44441/"), [&](const std::string& /*result*/) {});
    }
}
BENCHMARK(BM_Get);

/**
 * @brief This function is a benchmark test for the HTTP POST request.
 *
 * @param state Benchmark state.
 */
static void BM_Post(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().post(
            HttpURL("http://localhost:44441/"), R"({"foo": "bar"})", [&](const std::string& /*result*/) {});
    }
}
BENCHMARK(BM_Post);

/**
 * @brief This function is a benchmark test for the HTTP UPDATE request.
 *
 * @param state Benchmark state.
 */
static void BM_Update(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().update(
            HttpURL("http://localhost:44441/"), R"({"foo": "bar"})", [&](const std::string& /*result*/) {});
    }
}
BENCHMARK(BM_Update);

/**
 * @brief This function is a benchmark test for the HTTP DELETE request.
 *
 * @param state Benchmark state.
 */
static void BM_Delete(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().delete_(HttpURL("http://localhost:44441/12345"), [&](const std::string& /*result*/) {});
    }
}

BENCHMARK(BM_Delete);

/**
 * @brief This function is a benchmark test for the HTTP DOWNLOAD request.
 *
 * @param state Benchmark state.
 */
static void BM_Download(benchmark::State& state)
{
    for (auto _ : state)
    {
        HTTPRequest::instance().download(HttpURL("http://localhost:44441/"),
                                         "out.txt",
                                         [&](const std::string& /*result*/, const long /*responseCode*/) {});
    }
}
BENCHMARK(BM_Download);

BENCHMARK_MAIN();
