/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// Descriptors, connections and easy handles (plan-E2a-1 §Tests, lot B: D26 H8, D27 H2, the methods, RF-19).

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <set>

#include <curl/curl.h>

#include "componentFixture.hpp"
#include "fakeIndexer.hpp"
#include "rawTcpServer.hpp"

using namespace component;
using indexer_client::testing::FakeIndexer;
using indexer_client::testing::FakeIndexerOptions;
using indexer_client::testing::Rule;
using indexer_client::testing::SilentServer;

namespace
{
    std::atomic<std::uint64_t> g_easyInits {0};

    /// The descriptors curl itself creates (its multi's wake-up descriptor, a resolver's pair), as seen by the
    /// interposers below, and every close of one of them. Never destroyed: close() runs until the process ends.
    struct CurlDescriptors final
    {
        std::mutex mutex;
        bool recording {false};
        std::set<int> live; ///< Created by curl while recording and not closed yet.
        std::size_t created {0};
        std::size_t closedByCurl {0};
        std::vector<std::string> violations; ///< Closes by somebody else, of a closed number, or that failed.
    };

    CurlDescriptors& curlDescriptors()
    {
        static auto* descriptors = new CurlDescriptors();
        return *descriptors;
    }

    /// Whether `address` (a return address) lies in the shared object that carries libcurl.
    bool fromCurl(void* address)
    {
        Dl_info info {};
        return dladdr(address, &info) != 0 && info.dli_fname != nullptr &&
               std::strstr(info.dli_fname, "libwazuhext") != nullptr;
    }

    void trackIfCurl(int fd, void* caller)
    {
        if (fd < 0 || !fromCurl(caller))
        {
            return;
        }
        auto& descriptors = curlDescriptors();
        std::lock_guard<std::mutex> lock(descriptors.mutex);
        if (descriptors.recording)
        {
            descriptors.live.insert(fd);
            ++descriptors.created;
        }
    }

    void startRecording()
    {
        auto& descriptors = curlDescriptors();
        std::lock_guard<std::mutex> lock(descriptors.mutex);
        descriptors.live.clear();
        descriptors.created = 0;
        descriptors.closedByCurl = 0;
        descriptors.violations.clear();
        descriptors.recording = true;
    }

    std::set<int> liveCurlDescriptors()
    {
        auto& descriptors = curlDescriptors();
        std::lock_guard<std::mutex> lock(descriptors.mutex);
        return descriptors.live;
    }

    template<class F>
    F realFunction(const char* name)
    {
        return reinterpret_cast<F>(dlsym(RTLD_NEXT, name));
    }
} // namespace

namespace component
{
    std::uint64_t easyHandlesCreated()
    {
        return g_easyInits.load();
    }
} // namespace component

// Interposed (-rdynamic): the library's curl_easy_init calls are counted, then forwarded to libcurl in wazuhext.
extern "C" CURL* curl_easy_init()
{
    static const auto real = realFunction<CURL* (*)()>("curl_easy_init");
    g_easyInits.fetch_add(1);
    return real();
}

// Interposed: descriptors created from inside libwazuhext (curl) are recorded.
extern "C" int eventfd(unsigned int count, int flags)
{
    static const auto real = realFunction<int (*)(unsigned int, int)>("eventfd");
    const int fd = real(count, flags);
    trackIfCurl(fd, __builtin_return_address(0));
    return fd;
}

extern "C" int pipe2(int fds[2], int flags)
{
    static const auto real = realFunction<int (*)(int*, int)>("pipe2");
    const int rc = real(fds, flags);
    if (rc == 0)
    {
        trackIfCurl(fds[0], __builtin_return_address(0));
        trackIfCurl(fds[1], __builtin_return_address(0));
    }
    return rc;
}

extern "C" int socketpair(int domain, int type, int protocol, int fds[2])
{
    static const auto real = realFunction<int (*)(int, int, int, int*)>("socketpair");
    const int rc = real(domain, type, protocol, fds);
    if (rc == 0)
    {
        trackIfCurl(fds[0], __builtin_return_address(0));
        trackIfCurl(fds[1], __builtin_return_address(0));
    }
    return rc;
}

// Interposed: a curl descriptor must be closed by curl, once, while it is still open (H8).
extern "C" int close(int fd)
{
    static const auto real = realFunction<int (*)(int)>("close");
    auto& descriptors = curlDescriptors();
    bool tracked = false;
    {
        std::lock_guard<std::mutex> lock(descriptors.mutex);
        tracked = descriptors.recording && descriptors.live.erase(fd) != 0;
    }
    if (!tracked)
    {
        return real(fd);
    }
    const bool open = ::fcntl(fd, F_GETFD) != -1;
    const bool byCurl = fromCurl(__builtin_return_address(0));
    const int rc = real(fd);
    const int error = errno;
    std::lock_guard<std::mutex> lock(descriptors.mutex);
    if (byCurl && open && rc == 0)
    {
        ++descriptors.closedByCurl;
    }
    else
    {
        descriptors.violations.push_back(
            "fd " + std::to_string(fd) + (byCurl ? " closed by curl" : " closed by the transport") +
            (open ? "" : " after it was already closed") + (rc == 0 ? "" : std::string(": ") + std::strerror(error)));
    }
    errno = error;
    return rc;
}

// D26 (H8): a descriptor curl registers without opening it through the transport (the multi's wake-up descriptor)
// is watched while a transfer lives and, when curl stops wanting it, released: still open (curl owns it), its number
// not free for reuse, and closed exactly once, by curl, at the multi's cleanup.
TEST_F(TransportTest, ForeignDescriptorsReleasedNotClosed)
{
    FakeIndexer fake;
    fake.start();
    startRecording();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto curlOwned = liveCurlDescriptors();
    ASSERT_GE(curlOwned.size(), 1u) << "curl created no descriptor of its own";

    const auto first = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/one"));
    ASSERT_TRUE(collector->waitKey(first.key, 10s));
    ASSERT_EQ(collector->result(first.key)->status, 200);
    auto stats = transport->stats();
    EXPECT_GE(stats.foreignReleased, 1u) << "no foreign descriptor was ever watched and released";
    EXPECT_EQ(stats.foreignWatched, 0u) << "the transport still watches a foreign descriptor after the transfer";

    // Released, not closed: every descriptor curl owns is still open and still curl's.
    EXPECT_EQ(liveCurlDescriptors(), curlOwned);
    for (const int fd : curlOwned)
    {
        EXPECT_NE(::fcntl(fd, F_GETFD), -1) << "curl's fd " << fd << " was closed when the transport released it";
    }
    // Their numbers are not free: a descriptor opened now gets another number.
    const int mine = ::eventfd(0, EFD_CLOEXEC);
    ASSERT_GE(mine, 0);
    EXPECT_EQ(curlOwned.count(mine), 0u) << "fd " << mine << " was free for reuse while curl still owned it";

    // Watched and released again by later transfers.
    for (int i = 0; i < 10; ++i)
    {
        const auto next = submitTo(*transport, collector, request(HttpMethod::Get, fake.baseUrl() + "/again"));
        ASSERT_TRUE(collector->waitKey(next.key, 10s));
    }
    stats = transport->stats();
    EXPECT_GE(stats.foreignReleased, 2u);
    EXPECT_EQ(stats.foreignWatched, 0u);
    transport.reset();

    ASSERT_EQ(indexer_client::RuntimeOwner::shutdown(), indexer_client::Cause::None);
    const auto stillLive = liveCurlDescriptors();
    {
        auto& descriptors = curlDescriptors();
        std::lock_guard<std::mutex> lock(descriptors.mutex);
        descriptors.recording = false;
        for (const auto& violation : descriptors.violations)
        {
            ADD_FAILURE() << violation;
        }
        EXPECT_GE(descriptors.closedByCurl, curlOwned.size());
        std::cout << "[ INFO     ] curl descriptors created " << descriptors.created << ", closed by curl "
                  << descriptors.closedByCurl << std::endl;
    }
    for (const int fd : curlOwned)
    {
        EXPECT_EQ(stillLive.count(fd), 0u) << "curl's fd " << fd << " was never closed by curl";
    }
    // No double close reached a descriptor that took a released number.
    EXPECT_NE(::fcntl(mine, F_GETFD), -1) << "the test's own fd " << mine << " was closed by somebody else";
    ::close(mine);
}

// D27 (H2): connections are kept alive and reused: 1 000 POSTs over one loop use at most
// CURLMOPT_MAX_HOST_CONNECTIONS (8) connections.
TEST_F(TransportTest, KeepAliveReusesConnections)
{
    constexpr std::size_t REQUESTS = 1000;
    FakeIndexerOptions options;
    options.threads = 16;
    FakeIndexer fake(options);
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    const auto body = std::make_shared<const std::string>(R"({"index":{}})");
    for (std::size_t i = 0; i < REQUESTS; ++i)
    {
        ASSERT_TRUE(submitTo(*transport, collector, request(HttpMethod::Post, fake.baseUrl() + "/_bulk", body))
                        .admission.admitted);
    }
    ASSERT_TRUE(collector->waitTotal(REQUESTS, 60s)) << collector->total() << " of " << REQUESTS;
    std::size_t ok = 0;
    for (std::uint64_t key = 0; key < REQUESTS; ++key)
    {
        ok += collector->result(key)->status == 200 ? 1 : 0;
    }
    EXPECT_EQ(ok, REQUESTS);
    ASSERT_EQ(fake.requestCount(), REQUESTS);
    const auto connections = fake.distinctRemotePorts();
    EXPECT_GT(connections, 0u);
    EXPECT_LE(connections, 8u) << "connections were not reused";
    std::cout << "[ INFO     ] " << REQUESTS << " POST over " << connections << " connections" << std::endl;
}

// The method and the body are set on every use of an easy handle: POST → GET → DELETE with a body → HEAD on the same
// (reused) easy reach the server exactly as asked. A method the transport does not know (PATCH) is not admitted.
TEST_F(TransportTest, MethodAndBodyAfterReuse)
{
    FakeIndexerOptions options;
    options.recordBodies = true;
    FakeIndexer fake(options);
    fake.start();
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();

    struct Step final
    {
        HttpMethod method;
        const char* name;
        std::shared_ptr<const std::string> body;
    };
    const std::vector<Step> steps {
        {HttpMethod::Post, "POST", std::make_shared<const std::string>(R"({"post":1})")},
        {HttpMethod::Get, "GET", nullptr},
        {HttpMethod::Delete, "DELETE", std::make_shared<const std::string>(R"({"delete":2})")},
        {HttpMethod::Head, "HEAD", nullptr},
    };
    const auto easyBefore = easyHandlesCreated();
    std::vector<Submitted> sent;
    for (const auto& step : steps)
    {
        sent.push_back(
            submitTo(*transport, collector, request(step.method, fake.baseUrl() + "/m/" + step.name, step.body)));
        const auto& one = sent.back();
        ASSERT_TRUE(one.admission.admitted) << step.name;
        ASSERT_TRUE(collector->waitKey(one.key, 10s)) << step.name;
        EXPECT_EQ(collector->result(one.key)->status, 200) << step.name;
    }
    EXPECT_EQ(easyHandlesCreated() - easyBefore, 1u) << "the four transfers did not share one easy handle";

    const auto received = fake.requests();
    ASSERT_EQ(received.size(), steps.size());
    for (std::size_t i = 0; i < steps.size(); ++i)
    {
        const auto& step = steps[i];
        const auto& got = received[i];
        EXPECT_EQ(got.method, step.name);
        EXPECT_EQ(got.path, std::string("/m/") + step.name);
        EXPECT_EQ(got.body, step.body ? *step.body : std::string()) << step.name;
        EXPECT_EQ(got.bodySize, step.body ? step.body->size() : 0u) << step.name;
        if (!step.body)
        {
            const auto length = got.headers.find("Content-Length");
            EXPECT_TRUE(length == got.headers.end() || length->second == "0")
                << step.name << " inherited a body length: " << length->second;
            EXPECT_EQ(got.headers.count("Content-Type"), 0u) << step.name << " inherited a Content-Type";
        }
        else
        {
            EXPECT_EQ(got.headers.count("Expect"), 0u) << step.name << ": Expect must be suppressed";
        }
    }
    EXPECT_TRUE(collector->result(sent.back().key)->body.empty()) << "HEAD returns no body";

    const auto patch = submitTo(*transport, collector, request(static_cast<HttpMethod>(5), fake.baseUrl() + "/patch"));
    EXPECT_FALSE(patch.admission.admitted) << "PATCH is not a transport method";
    EXPECT_EQ(patch.admission.cause, indexer_client::Cause::InvalidArgument);
    EXPECT_EQ(patch.admission.id, 0u);
    EXPECT_FALSE(collector->waitKey(patch.key, 200ms)) << "a request that was not admitted got a callback";
    EXPECT_EQ(fake.requestCount(), steps.size());
}

// RF-19: until E2a-2 brings TLS, an https:// URL is not admitted (no callback) and opens no connection.
TEST_F(TransportTest, HttpsNotAdmittedUntilTls)
{
    SilentServer server;
    auto transport = startRuntime(1, 2);
    ASSERT_NE(transport, nullptr);
    auto collector = Collector::create();
    const auto rejectedBefore = transport->stats().rejected;

    const auto authority = "127.0.0.1:" + std::to_string(server.port());
    std::vector<Submitted> refused;
    for (const auto& url : {"https://" + authority + "/", "HTTPS://" + authority + "/x", "ftp://" + authority + "/"})
    {
        for (const auto method : {HttpMethod::Get, HttpMethod::Post})
        {
            refused.push_back(submitTo(*transport, collector, request(method, url)));
            EXPECT_FALSE(refused.back().admission.admitted) << url;
            EXPECT_EQ(refused.back().admission.cause, indexer_client::Cause::InvalidArgument) << url;
            EXPECT_EQ(refused.back().admission.id, 0u) << url;
        }
    }
    EXPECT_FALSE(server.waitForAccepted(1, 300ms)) << "a refused URL opened a connection";
    EXPECT_EQ(server.acceptedCount(), 0u);
    EXPECT_EQ(collector->total(), 0u) << "a request that was not admitted got a callback";
    const auto stats = transport->stats();
    EXPECT_EQ(stats.rejected - rejectedBefore, refused.size());
    EXPECT_EQ(stats.admitted, 0u);
}
