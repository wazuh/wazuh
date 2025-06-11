// bench/udsrv_bench.cpp

#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <benchmark/benchmark.h>

#include <udgramsrv/udsrv.hpp>

// Randomly generated socket path
static std::string makeSocketPath()
{
    return "/tmp/udsrv_bench_" + std::to_string(getpid()) + ".sock";
}

// Check the latency of starting and stopping the server
// This benchmark measures the time taken to start and stop the server with a given pool size.
static void BM_ServerStartStop(benchmark::State& state)
{
    const size_t poolSize = state.range(0);
    for (auto _ : state)
    {
        auto path = makeSocketPath();
        // handler vacío
        udsrv::Server srv([](std::string&&) {}, path);
        benchmark::DoNotOptimize(srv);
        srv.start(poolSize);
        srv.stop();
        ::unlink(path.c_str());
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ServerStartStop)->Arg(1)->Arg(2)->Arg(4)->Arg(8);

// Helper dispatch function for sending messages to the server
// This fixture creates a client socket that can send messages to the server and waits for a response.
struct DispatchFixture
{
    std::string socketPath;
    int cliSock {-1};
    sockaddr_un cliAddr {};
    std::mutex mtx;
    std::condition_variable cv;
    bool received {false};

    DispatchFixture()
    {
        socketPath = makeSocketPath();
        cliSock = ::socket(AF_UNIX, SOCK_DGRAM, 0);
        cliAddr.sun_family = AF_UNIX;
        std::strncpy(cliAddr.sun_path, socketPath.c_str(), sizeof(cliAddr.sun_path) - 1);
    }
    ~DispatchFixture()
    {
        if (cliSock >= 0)
            ::close(cliSock);
        ::unlink(socketPath.c_str());
    }

    void sendAndWait(const std::string& msg)
    {
        {
            std::lock_guard lk(mtx);
            received = false;
        }
        ssize_t n = ::sendto(cliSock,
                             msg.data(),
                             msg.size(),
                             0,
                             reinterpret_cast<sockaddr*>(&cliAddr),
                             offsetof(sockaddr_un, sun_path) + socketPath.size());
        if (n < 0)
        {
            throw std::runtime_error("DispatchFixture: sendto() failed");
        }
        // Wait for the server to call the handler and notify us
        std::unique_lock ul(mtx);
        cv.wait(ul, [&] { return received; });
    }
};

// Check the latency of a single dispatch
static void BM_ServerSingleDispatch(benchmark::State& state)
{
    const size_t poolSize = state.range(0);
    DispatchFixture fix;

    udsrv::Server srv(
        [&](std::string&&)
        {
            std::lock_guard lk(fix.mtx);
            fix.received = true;
            fix.cv.notify_one();
        },
        fix.socketPath);
    srv.start(poolSize);

    const std::string payload = "hello_benchmark";
    for (auto _ : state)
    {
        fix.sendAndWait(payload);
    }

    srv.stop();
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ServerSingleDispatch)->Arg(1)->Arg(2)->Arg(4)->Arg(8);

BENCHMARK_MAIN();
