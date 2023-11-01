#include <benchmark/benchmark.h>

// Incluye tu clase ConcurrentQueue aquí
#include <queue/concurrentQueue.hpp>
#include <mocks/fakeMetric.hpp>

using namespace base::queue;

class Dummy
{
public:
    int value;

    Dummy(int v)
        : value(v)
    {
    }

    std::string str() const { return "Dummy: " + std::to_string(value); }
};

static void initLogging(const benchmark::State& s)
{
    static bool initialized = false;

    if (!initialized)
    {
        // Logging setup
        logging::LoggingConfig logConfig;
        logConfig.logLevel = "off";
        logConfig.filePath = "";
        logging::loggingInit(logConfig);
        initialized = true;
    }
}

// Define una prueba de rendimiento para usar solo la cola de baja prioridad
static void BM_OnlyLowPriorityQueue(benchmark::State& state)
{
    ConcurrentQueue<std::shared_ptr<Dummy>> cq(
    1000000, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());

    for (auto i = 0; i < 1000000; i++)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    std::shared_ptr<Dummy> element;

    for (auto _ : state)
    {
        cq.waitPop(element, 10);
    }
}
BENCHMARK(BM_OnlyLowPriorityQueue)->Setup(initLogging);

// Define una prueba de rendimiento para usar solo la cola de baja prioridad
static void BM_OnlyHighPriorityQueue(benchmark::State& state)
{
    ConcurrentQueue<std::shared_ptr<Dummy>> cq(
    1000000, std::make_shared<FakeMetricScope>(), std::make_shared<FakeMetricScope>());

    for (auto i = 0; i < 1000000; i++)
    {
        cq.push(std::make_shared<Dummy>(i), true);
    }

    std::shared_ptr<Dummy> element;

    for (auto _ : state)
    {
        cq.waitPop(element, 10);
    }
}
BENCHMARK(BM_OnlyHighPriorityQueue)->Setup(initLogging);

