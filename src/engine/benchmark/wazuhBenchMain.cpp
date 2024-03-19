#include <benchmark/benchmark.h>
#include <logging/logging.hpp>

int main(int argc, char **argv)
{
    logging::LoggingConfig logConfig;
    logConfig.level = "off";
    logging::start(logConfig);

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
