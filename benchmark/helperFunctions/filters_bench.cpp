#include "builders/opBuilderHelperFilter.hpp"

#include <benchmark/benchmark.h>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <expression.hpp>
#include <json/json.hpp>

/******
 * Base event:
 * {
 *   "wazuh": {
 *     "queue": 49,
 *     "origin": "/var/cosas"
 *   },
 *   "agent": {
 *     "id": "0",
 *     "name": "hostname0",
 *     "registeredIP": "any"
 *   },
 *   "event": {
 *     "original": "TEST MSG"
 *   }
 * }
 */

/**************************************************************
 *                 opBuilderHelperIntEqual
 **************************************************************/

static void opBuilderHelperIntEqual_success(benchmark::State& state)
{
    auto tuple = std::make_tuple(std::string {"/wazuh/queue"},
                                 std::string {"int_equal"},
                                 std::vector<std::string> {"10"},
                                 std::make_shared<defs::mocks::FailDef>());

    base::Event event1 = std::make_shared<json::Json>(R"({"wazuh":{"queue":10,"origin":"/var/cosas"},
                                                          "agent":{"id":"0","name":"hostname0","registeredIP":"any"},
                                                          "event":{"original":"TEST MSG"}})");

    auto op = std::apply(builder::internals::builders::opBuilderHelperIntEqual, tuple)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();

    for (auto _ : state)
    {
        base::result::Result<base::Event> result = op(event1);
        benchmark::DoNotOptimize(result);
        if (result.failure())
        {
            state.SkipWithError(result.trace().c_str());
        }
    }
}
BENCHMARK(opBuilderHelperIntEqual_success)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();

// opBuilderHelperIntEqual
static void opBuilderHelperIntEqual_fail(benchmark::State& state)
{
    auto tuple = std::make_tuple(std::string {"/wazuh/queue"},
                                 std::string {"int_equal"},
                                 std::vector<std::string> {"11"},
                                 std::make_shared<defs::mocks::FailDef>());

    base::Event event1 = std::make_shared<json::Json>(R"({"wazuh":{"queue":10,"origin":"/var/cosas"},
                                                          "agent":{"id":"0","name":"hostname0","registeredIP":"any"},
                                                          "event":{"original":"TEST MSG"}})");

    auto op = std::apply(builder::internals::builders::opBuilderHelperIntEqual, tuple)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();

    for (auto _ : state)
    {
        base::result::Result<base::Event> result = op(event1);
        benchmark::DoNotOptimize(result);
        if (result.success())
        {
            state.SkipWithError(result.trace().c_str());
        }
    }
}
BENCHMARK(opBuilderHelperIntEqual_fail)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();

/**************************************************************
 *                 opBuilderHelperStringStarts
 **************************************************************/
// opBuilderHelperStringStarts
static void opBuilderHelperStringStarts_success(benchmark::State& state)
{
    auto tuple = std::make_tuple(std::string {"/agent/name"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"specificHost"},
                                 std::make_shared<defs::mocks::FailDef>());

    base::Event event1 = std::make_shared<json::Json>(R"({"wazuh":{"queue":10,"origin":"/var/cosas"},
                                                          "agent":{"id":"0","name":"specificHost_001",
                                                          "registeredIP":"any"},"event":{"original":"TEST MSG"}})");

    auto op = std::apply(builder::internals::builders::opBuilderHelperStringStarts, tuple)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();

    for (auto _ : state)
    {
        base::result::Result<base::Event> result = op(event1);
        benchmark::DoNotOptimize(result);
        if (result.failure())
        {
            state.SkipWithError(result.trace().c_str());
        }
    }
}
BENCHMARK(opBuilderHelperStringStarts_success)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();

static void opBuilderHelperStringStarts_fail(benchmark::State& state)
{
    auto tuple = std::make_tuple(std::string {"/agent/name"},
                                 std::string {"starts_with"},
                                 std::vector<std::string> {"otherHost"},
                                 std::make_shared<defs::mocks::FailDef>());

    base::Event event1 = std::make_shared<json::Json>(R"({"wazuh":{"queue":10,"origin":"/var/cosas"},
                                                          "agent":{"id":"0","name":"specificHost_001",
                                                          "registeredIP":"any"},"event":{"original":"TEST MSG"}})");

    auto op = std::apply(builder::internals::builders::opBuilderHelperStringStarts, tuple)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();

    for (auto _ : state)
    {
        base::result::Result<base::Event> result = op(event1);
        benchmark::DoNotOptimize(result);
        if (result.success())
        {
            state.SkipWithError(result.trace().c_str());
        }
    }
}
BENCHMARK(opBuilderHelperStringStarts_fail)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();

/**************************************************************
 *                 opBuilderHelperIPCIDR
 **************************************************************/
// opBuilderHelperIPCIDR
static void opBuilderHelperIPCIDR_success(benchmark::State& state)
{
    auto tuple = std::make_tuple(std::string {"/agent/registeredIP"},
                                 std::string {"ip_in_cidr"},
                                 std::vector<std::string> {"192.168.0.0", "24"},
                                 std::make_shared<defs::mocks::FailDef>());

    base::Event event1 = std::make_shared<json::Json>(R"({"wazuh":{"queue":10,"origin":"/var/cosas"},
                                                          "agent":{"id":"0","name":"specificHost_001",
                                                          "registeredIP":"192.168.0.10"},
                                                          "event":{"original":"TEST MSG"}})");

    auto op = std::apply(builder::internals::builders::opBuilderHelperIPCIDR, tuple)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();
    for (auto _ : state)
    {
        base::result::Result<base::Event> result = op(event1);
        benchmark::DoNotOptimize(result);
        if (result.failure())
        {
            state.SkipWithError(result.trace().c_str());
        }
    }
}
BENCHMARK(opBuilderHelperIPCIDR_success)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();

static void opBuilderHelperIPCIDR_fail(benchmark::State& state)
{
    auto tuple = std::make_tuple(std::string {"/agent/registeredIP"},
                                 std::string {"ip_in_cidr"},
                                 std::vector<std::string> {"192.168.0.0", "24"},
                                 std::make_shared<defs::mocks::FailDef>());

    base::Event event1 = std::make_shared<json::Json>(R"({"wazuh":{"queue":10,"origin":"/var/cosas"},
                                                          "agent":{"id":"0","name":"specificHost_001",
                                                          "registeredIP":"10.0.0.10"},
                                                          "event":{"original":"TEST MSG"}})");

    auto op = std::apply(builder::internals::builders::opBuilderHelperIPCIDR, tuple)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();
    for (auto _ : state)
    {
        base::result::Result<base::Event> result = op(event1);
        benchmark::DoNotOptimize(result);
        if (result.success())
        {
            state.SkipWithError(result.trace().c_str());
        }
    }
}
BENCHMARK(opBuilderHelperIPCIDR_fail)->Threads(1)->Threads(2)->Threads(4)->UseRealTime();
