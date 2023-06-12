#include <benchmark/benchmark.h>
#include <logging/logging.hpp>

int main(int argc, char **argv)
{
    logging::LoggingConfig logConfig;
    logConfig.logLevel = "off";
    logging::loggingInit(logConfig);

    benchmark::Initialize(&argc, argv);
    if (benchmark::ReportUnrecognizedArguments(argc, argv))
        return 1;
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();
    return 0;
}
