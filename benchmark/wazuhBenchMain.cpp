#include <benchmark/benchmark.h>
#include <base/logging.hpp>

int main(int argc, char **argv)
{
    logging::testInit();

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
