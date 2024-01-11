/*
 * Wazuh - Content Migration tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 03, 2023.
 *
 */

#include <benchmark/benchmark.h>
#include <filesystem>

int main(int argc, char** argv)
{
    benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv))
    {
        return EXIT_FAILURE;
    }
    benchmark::RunSpecifiedBenchmarks();
    benchmark::Shutdown();

    return EXIT_SUCCESS;
}
