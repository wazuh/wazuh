#include <re2/re2.h>
#include <regex>

#include "benchmark/benchmark.h"

static void re2_partial_bench(benchmark::State & state)
{
    for (auto _ : state)
    {
        RE2::PartialMatch("protocol://server/path",
                          "([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?");
        RE2::PartialMatch("client@wazuh.com", "([^ @]+)@([^ @]+)");
        RE2::PartialMatch("23/11/2015",
                          "([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)");
        RE2::PartialMatch("client@wazuh.com",
                          "([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)");
    }
}

BENCHMARK(re2_partial_bench);

static void std_partial_bench(benchmark::State & state)
{
    for (auto _ : state)
    {
        std::regex_search("protocol://server/path",
                          std::regex("([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?"));
        std::regex_search("client@wazuh.com", std::regex("([^ @]+)@([^ @]+)"));
        std::regex_search(
            "23/11/2015",
            std::regex("([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)"));
        std::regex_search(
            "client@wazuh.com",
            std::regex("([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)"));
    }
}

BENCHMARK(std_partial_bench);

static void re2_partial_bench_precompiled(benchmark::State & state)
{

    RE2 re1("([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?");
    RE2 re2("([^ @]+)@([^ @]+)");
    RE2 re3("([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)");
    RE2 re4("([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)");

    for (auto _ : state)
    {
        RE2::PartialMatch("protocol://server/path", re1);
        RE2::PartialMatch("client@wazuh.com", re2);
        RE2::PartialMatch("23/11/2015", re3);
        RE2::PartialMatch("client@wazuh.com", re4);
    }
}

BENCHMARK(re2_partial_bench_precompiled);

static void re2_full_bench(benchmark::State & state)
{
    for (auto _ : state)
    {
        RE2::FullMatch("protocol://server/path",
                       "([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?");
        RE2::FullMatch("client@wazuh.com", "([^ @]+)@([^ @]+)");
        RE2::FullMatch("23/11/2015",
                       "([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)");
        RE2::FullMatch("client@wazuh.com",
                       "([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)");
    }
}

BENCHMARK(re2_full_bench);

static void std_full_bench(benchmark::State & state)
{
    for (auto _ : state)
    {
        std::regex_match("protocol://server/path",
                         std::regex("([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?"));
        std::regex_match("client@wazuh.com", std::regex("([^ @]+)@([^ @]+)"));
        std::regex_match(
            "23/11/2015",
            std::regex("([0-9][0-9]?)/([0-9][0-9]?)/([0-9][0-9]([0-9][0-9])?)"));
        std::regex_match(
            "client@wazuh.com",
            std::regex("([a-zA-Z][a-zA-Z0-9]*)://([^ /]+)(/[^ ]*)?|([^ @]+)@([^ @]+)"));
    }
}

BENCHMARK(std_full_bench);
