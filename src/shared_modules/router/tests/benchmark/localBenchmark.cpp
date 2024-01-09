#include "routerModule.hpp"
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <atomic>
#include <benchmark/benchmark.h>
#include <chrono>
#include <iostream>

/**
 * @brief ReceptionPerformanceFixture class.
 *
 */
class ReceptionPerformanceFixture : public benchmark::Fixture
{
protected:
    std::unique_ptr<RouterProvider> publisher; ///< Publisher used on benchmark.

public:
    /**
     * @brief Benchmark setup routine.
     *
     * @param state Benchmark state.
     */
    void SetUp(const ::benchmark::State& state) override
    {
        RouterModule::instance().start();

        publisher = std::make_unique<RouterProvider>("test");
        publisher->start();

        countingLambda = [&](const std::vector<char>& data)
        {
            ++count;
        };
        subscriptor = std::make_unique<RouterSubscriber>("test", "subscriberTest");
        subscriptor->subscribe(countingLambda);
    }

    /**
     * @brief Benchmark teardown routine.
     *
     * @param state Benchmark state.
     */
    void TearDown(const ::benchmark::State& state) override
    {
        RouterModule::instance().stop();
    }

private:
    std::atomic<size_t> count = 0;
    std::function<void(const std::vector<char>&)> countingLambda;
    std::unique_ptr<RouterSubscriber> subscriptor;
};

BENCHMARK_DEFINE_F(ReceptionPerformanceFixture, ReceptionPerformance)(benchmark::State& state)
{
    std::string data_str {"Hello world"};
    auto data = std::vector<char>(data_str.begin(), data_str.end());

    for (auto _ : state)
    {
        publisher->send(data);
    }
}

BENCHMARK_REGISTER_F(ReceptionPerformanceFixture, ReceptionPerformance)->Iterations(1000000)->Threads(1);

BENCHMARK_MAIN();
