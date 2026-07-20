#include <benchmark/benchmark.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>

#include <base/dotPath.hpp>
#include <base/json.hpp>
#include <geo/ilocator.hpp>

#include "dbHandle.hpp"
#include "dbInstance.hpp"
#include "locator.hpp"

namespace
{

// ─────────────────────────────────────────────────────────────────────────────
// IPs present in the test MMDB
// ─────────────────────────────────────────────────────────────────────────────

constexpr const char* IP_FOUND = "1.2.3.4";
constexpr const char* IP_FOUND2 = "1.2.3.5";
constexpr const char* IP_NOT_FOUND = "1.2.3.6";

// ─────────────────────────────────────────────────────────────────────────────
// Fixture: build a real Locator once per benchmark run
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Creates a real geo::Locator backed by the project test MMDB file.
 *
 * The database file is copied to a temporary path (required by the Locator/DbInstance
 * implementation which uses mmap) and is cleaned up when the returned Locator is
 * destroyed – the destructor of the DbInstance closes the MMDB handle, and the
 * temporary file is removed by the RAII wrapper below.
 */
struct LocatorFixture
{
    std::string tmpPath;
    std::shared_ptr<geo::DbHandle> handle;
    std::shared_ptr<geo::Locator> locator;

    explicit LocatorFixture(geo::Type type = geo::Type::CITY)
    {
        // Copy the test database to a uniquely-named temp file
        char tpl[] = "/tmp/geo_bench_XXXXXX";
        int fd = mkstemp(tpl);
        if (fd == -1)
            throw std::runtime_error("mkstemp failed");

        tmpPath = std::string(tpl) + ".mmdb";
        if (std::rename(tpl, tmpPath.c_str()) != 0)
        {
            std::remove(tpl);
            throw std::runtime_error("rename failed");
        }

        {
            std::ifstream src(MMDB_PATH_TEST, std::ios::binary);
            if (!src)
                throw std::runtime_error("Cannot open test MMDB: " MMDB_PATH_TEST);
            std::ofstream dst(tmpPath, std::ios::binary);
            dst << src.rdbuf();
        }

        // Build the handle + instance
        handle = std::make_shared<geo::DbHandle>();
        handle->store(std::make_shared<geo::DbInstance>(tmpPath, "bench-hash", 0, type));
        locator = std::make_shared<geo::Locator>(handle);
    }

    ~LocatorFixture()
    {
        locator.reset();
        handle.reset();
        std::filesystem::remove(tmpPath);
    }

    LocatorFixture(const LocatorFixture&) = delete;
    LocatorFixture& operator=(const LocatorFixture&) = delete;
};

// ─────────────────────────────────────────────────────────────────────────────
// getString benchmarks
// (mirrors: mapGeoToECS city_name, continent_code, country_iso_code, …)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getString – cache hit path.
 * The same IP is used every iteration so the MMDB lookup is performed only once;
 * subsequent calls skip straight to field extraction.
 */
static void BM_Locator_getString_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_map.test_str1"};

    fix.locator->getString(IP_FOUND, path);

    for (auto _ : state)
    {
        auto result = fix.locator->getString(IP_FOUND, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getString_CacheHit);

/**
 * getString – cache miss path.
 * Two IPs alternate every iteration, forcing a fresh MMDB_lookup_string call each time.
 */
static void BM_Locator_getString_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_map.test_str1"};
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;
        auto result = fix.locator->getString(ip, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getString_CacheMiss);

/**
 * getString – IP not found in database.
 * Measures the cost of the not-found error path (IP_TRANSLATION / IP_NOT_FOUND).
 */
static void BM_Locator_getString_NotFound(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_map.test_str1"};

    for (auto _ : state)
    {
        auto result = fix.locator->getString(IP_NOT_FOUND, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getString_NotFound);

/**
 * getString – field path not found in record (wrong path, but IP is present).
 * Isolates the MMDB_aget_value miss path from the IP-lookup miss path.
 */
static void BM_Locator_getString_FieldNotFound(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"nonexistent_field"};

    fix.locator->getString(IP_FOUND, DotPath {"test_map.test_str1"});

    for (auto _ : state)
    {
        auto result = fix.locator->getString(IP_FOUND, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getString_FieldNotFound);

// ─────────────────────────────────────────────────────────────────────────────
// getDouble benchmarks
// (mirrors: mapGeoToECS location.latitude / location.longitude)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getDouble – cache hit path.
 */
static void BM_Locator_getDouble_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_double"};

    fix.locator->getDouble(IP_FOUND, path);

    for (auto _ : state)
    {
        auto result = fix.locator->getDouble(IP_FOUND, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getDouble_CacheHit);

/**
 * getDouble – cache miss path.
 */
static void BM_Locator_getDouble_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_double"};
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;
        auto result = fix.locator->getDouble(ip, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getDouble_CacheMiss);

// ─────────────────────────────────────────────────────────────────────────────
// getUint32 benchmarks
// (mirrors: mapAStoECS autonomous_system_number)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getUint32 – cache hit path.
 */
static void BM_Locator_getUint32_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_uint32"};

    fix.locator->getUint32(IP_FOUND, path);

    for (auto _ : state)
    {
        auto result = fix.locator->getUint32(IP_FOUND, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getUint32_CacheHit);

/**
 * getUint32 – cache miss path.
 */
static void BM_Locator_getUint32_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_uint32"};
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;
        auto result = fix.locator->getUint32(ip, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getUint32_CacheMiss);

// ─────────────────────────────────────────────────────────────────────────────
// getAsJson benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getAsJson – cache hit path, scalar string field.
 */
static void BM_Locator_getAsJson_Scalar_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_map.test_str1"};

    fix.locator->getAsJson(IP_FOUND, path);

    for (auto _ : state)
    {
        auto result = fix.locator->getAsJson(IP_FOUND, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getAsJson_Scalar_CacheHit);

/**
 * getAsJson – cache miss path, scalar string field.
 */
static void BM_Locator_getAsJson_Scalar_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    const DotPath path {"test_map.test_str1"};
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;
        auto result = fix.locator->getAsJson(ip, path);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getAsJson_Scalar_CacheMiss);

// ─────────────────────────────────────────────────────────────────────────────
// getAll benchmarks
// (full-record dump – not in the enrichment hot-path but part of ILocator API)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getAll – cache hit path.
 * Even though the IP lookup is cached, getAll must walk the full entry-data list and
 * build a json::Json object, so this measures the serialisation cost alone.
 */
static void BM_Locator_getAll_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;

    fix.locator->getAll(IP_FOUND);

    for (auto _ : state)
    {
        auto result = fix.locator->getAll(IP_FOUND);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getAll_CacheHit);

/**
 * getAll – cache miss path.
 * Combines a fresh MMDB lookup with a full record dump each iteration.
 */
static void BM_Locator_getAll_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;
        auto result = fix.locator->getAll(ip);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getAll_CacheMiss);

/**
 * getAll – IP not found path.
 */
static void BM_Locator_getAll_NotFound(benchmark::State& state)
{
    LocatorFixture fix;

    for (auto _ : state)
    {
        auto result = fix.locator->getAll(IP_NOT_FOUND);
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_getAll_NotFound);

// ─────────────────────────────────────────────────────────────────────────────
// Enrichment-pattern benchmarks
// Simulate the exact call sequence executed by mapGeoToECS / mapAStoECS in geo.cpp
// for a single IP, without the expression-graph overhead.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Full mapGeoToECS call pattern – cache hit.
 * Calls getString for every city field and getDouble for lat/lon, matching the
 * order in mapGeoToECS, with the same IP cached across iterations.
 */
static void BM_Locator_mapGeoPattern_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;
    const std::string ip {IP_FOUND};

    fix.locator->getString(ip, "test_map.test_str1");

    for (auto _ : state)
    {
        // getString calls (11 fields in mapGeoToECS)
        auto r1 = fix.locator->getString(ip, "test_map.test_str1"); // city_name
        auto r2 = fix.locator->getString(ip, "test_map.test_str1"); // continent_code
        auto r3 = fix.locator->getString(ip, "test_map.test_str1"); // continent_name
        auto r4 = fix.locator->getString(ip, "test_map.test_str1"); // country_iso_code
        auto r5 = fix.locator->getString(ip, "test_map.test_str1"); // country_name
        auto r6 = fix.locator->getString(ip, "test_map.test_str1"); // postal_code
        auto r7 = fix.locator->getString(ip, "test_map.test_str1"); // timezone
        auto r8 = fix.locator->getString(ip, "test_map.test_str1"); // region_iso_code
        auto r9 = fix.locator->getString(ip, "test_map.test_str1"); // region_name
        // getDouble calls (2 fields in mapGeoToECS)
        auto r10 = fix.locator->getDouble(ip, "test_double"); // latitude
        auto r11 = fix.locator->getDouble(ip, "test_double"); // longitude

        benchmark::DoNotOptimize(r1);
        benchmark::DoNotOptimize(r11);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_mapGeoPattern_CacheHit);

/**
 * Full mapGeoToECS call pattern – cache miss.
 * Alternates IPs to force an MMDB lookup before each batch of field extractions.
 */
static void BM_Locator_mapGeoPattern_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;

        auto r1 = fix.locator->getString(ip, "test_map.test_str1");
        auto r2 = fix.locator->getString(ip, "test_map.test_str1");
        auto r3 = fix.locator->getString(ip, "test_map.test_str1");
        auto r4 = fix.locator->getString(ip, "test_map.test_str1");
        auto r5 = fix.locator->getString(ip, "test_map.test_str1");
        auto r6 = fix.locator->getString(ip, "test_map.test_str1");
        auto r7 = fix.locator->getString(ip, "test_map.test_str1");
        auto r8 = fix.locator->getString(ip, "test_map.test_str1");
        auto r9 = fix.locator->getString(ip, "test_map.test_str1");
        auto r10 = fix.locator->getDouble(ip, "test_double");
        auto r11 = fix.locator->getDouble(ip, "test_double");

        benchmark::DoNotOptimize(r1);
        benchmark::DoNotOptimize(r11);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_mapGeoPattern_CacheMiss);

/**
 * Full mapAStoECS call pattern – cache hit.
 * Calls getUint32 (AS number) and getString (AS organisation), matching mapAStoECS.
 */
static void BM_Locator_mapASPattern_CacheHit(benchmark::State& state)
{
    LocatorFixture fix;
    const std::string ip {IP_FOUND};

    fix.locator->getUint32(ip, "test_uint32");

    for (auto _ : state)
    {
        auto r1 = fix.locator->getUint32(ip, "test_uint32");        // autonomous_system_number
        auto r2 = fix.locator->getString(ip, "test_map.test_str1"); // autonomous_system_organization

        benchmark::DoNotOptimize(r1);
        benchmark::DoNotOptimize(r2);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_mapASPattern_CacheHit);

/**
 * Full mapAStoECS call pattern – cache miss.
 */
static void BM_Locator_mapASPattern_CacheMiss(benchmark::State& state)
{
    LocatorFixture fix;
    bool toggle = false;

    for (auto _ : state)
    {
        const char* ip = toggle ? IP_FOUND : IP_FOUND2;
        toggle = !toggle;

        auto r1 = fix.locator->getUint32(ip, "test_uint32");
        auto r2 = fix.locator->getString(ip, "test_map.test_str1");

        benchmark::DoNotOptimize(r1);
        benchmark::DoNotOptimize(r2);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Locator_mapASPattern_CacheMiss);

// ─────────────────────────────────────────────────────────────────────────────
// Manager::getLocator benchmark
// (cost of obtaining a new Locator instance from the Manager)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Measures the overhead of Manager::getLocator() – i.e., creating a new
 * geo::Locator (shared_ptr allocation + shared_lock on the map) without any
 * subsequent lookup.  Useful to understand the cost paid when a fresh Locator
 * is requested at pipeline build time.
 */
static void BM_Manager_getLocator(benchmark::State& state)
{
    LocatorFixture fix;

    for (auto _ : state)
    {
        // Directly exercise DbHandle::load() + Locator construction, which is
        // what Manager::getLocator does internally.
        auto inst = fix.handle->load();
        auto locator = std::make_shared<geo::Locator>(fix.handle);
        benchmark::DoNotOptimize(locator);
        benchmark::DoNotOptimize(inst);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_Manager_getLocator);

} // namespace

BENCHMARK_MAIN();
