#include <benchmark/benchmark.h>

#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <ctistore/ctistoragedb.hpp>
#include <base/json.hpp>

using namespace cti::store;

namespace
{
    const std::filesystem::path CTI_BENCHMARK_PATH = std::filesystem::temp_directory_path() / "cti_benchmark";

    std::filesystem::path uniquePath(const std::string& path)
    {
        auto pid = getpid();
        auto tid = std::this_thread::get_id();
        std::stringstream ss;
        ss << pid << "_" << tid << "/"; // Unique path per thread and process
        return std::filesystem::path(path) / ss.str();
    }
}

class CTIStorageBenchmark
{
public:
    CTIStorageBenchmark()
    {
        // Create unique benchmark database path to avoid conflicts
        m_testDbPath = uniquePath(CTI_BENCHMARK_PATH);
        if (std::filesystem::exists(m_testDbPath))
        {
            std::filesystem::remove_all(m_testDbPath);
        }
        std::filesystem::create_directories(m_testDbPath.parent_path());
        m_storage = std::make_unique<CTIStorageDB>(m_testDbPath.string(), false);
    }

    ~CTIStorageBenchmark()
    {
        m_storage.reset();
        if (std::filesystem::exists(m_testDbPath))
        {
            std::filesystem::remove_all(m_testDbPath);
        }
    }

    json::Json createSamplePolicy(const std::string& name, int version = 1)
    {
        json::Json policy;
        policy.setObject();
        policy.setString(name, "/name");
        policy.setInt(1, "/offset");
        policy.setInt(version, "/version");
        policy.setString("2025-09-26T10:00:00.000Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("policy", "/type");

        json::Json document;
        document.setObject();
        document.setString("Wazuh 5.0", "/title");
        document.setBool(true, "/enabled");

        json::Json metadata;
        metadata.setObject();
        metadata.setString(name, "/id");
        metadata.setString("Wazuh Inc.", "/author");
        metadata.setString("2025-09-26T10:00:00.000Z", "/date");
        metadata.setString("Benchmark policy", "/description");
        metadata.setString("", "/documentation");

        json::Json references;
        references.setArray();
        references.appendString("https://wazuh.com");
        metadata.set("/references", references);

        document.set("/metadata", metadata);
        payload.set("/document", document);

        json::Json integrations;
        integrations.setArray();
        payload.set("/integrations", integrations);

        policy.set("/payload", payload);
        return policy;
    }

    json::Json createSampleIntegration(const std::string& id, const std::string& title)
    {
        json::Json integration;
        integration.setObject();
        integration.setString(id, "/name");
        integration.setInt(2, "/offset");
        integration.setInt(1, "/version");
        integration.setString("2025-09-26T10:00:00.000Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("integration", "/type");

        json::Json document;
        document.setObject();
        document.setString("Wazuh Inc.", "/author");
        document.setString("2025-09-26T10:00:00.000Z", "/date");
        document.setString("Integration description", "/description");
        document.setBool(true, "/enabled");
        document.setString(id, "/id");
        document.setString(title, "/title");

        json::Json decoders;
        decoders.setArray();
        document.set("/decoders", decoders);

        json::Json kvdbs;
        kvdbs.setArray();
        document.set("/kvdbs", kvdbs);

        json::Json references;
        references.setArray();
        references.appendString("https://wazuh.com");
        document.set("/references", references);

        payload.set("/document", document);
        integration.set("/payload", payload);

        return integration;
    }

    json::Json createSampleDecoder(const std::string& id, const std::string& title, const std::string& integrationId = "")
    {
        json::Json decoder;
        decoder.setObject();
        decoder.setString(id, "/name");
        decoder.setInt(4, "/offset");
        decoder.setInt(1, "/version");
        decoder.setString("2025-09-26T10:00:00.000Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("decoder", "/type");
        if (!integrationId.empty())
        {
            payload.setString(integrationId, "/integration_id");
        }

        json::Json document;
        document.setObject();
        document.setString("condition_string", "/check");
        document.setString("2025-09-26T10:00:00.000Z", "/date");
        document.setBool(true, "/enabled");
        document.setString(id, "/id");
        document.setString(title, "/name");

        json::Json definitions;
        definitions.setObject();
        document.set("/definitions", definitions);

        json::Json metadata;
        metadata.setObject();
        document.set("/metadata", metadata);

        json::Json normalize;
        normalize.setArray();
        document.set("/normalize", normalize);

        json::Json parse;
        parse.setObject();
        document.set("/parse", parse);

        payload.set("/document", document);
        decoder.set("/payload", payload);

        return decoder;
    }

    json::Json createSampleKVDB(const std::string& id, const std::string& title, const std::string& integrationId = "")
    {
        json::Json kvdb;
        kvdb.setObject();
        kvdb.setString(id, "/name");
        kvdb.setInt(8, "/offset");
        kvdb.setInt(1, "/version");
        kvdb.setString("2025-09-26T10:00:00.000Z", "/inserted_at");

        json::Json payload;
        payload.setObject();
        payload.setString("kvdb", "/type");
        if (!integrationId.empty())
        {
            payload.setString(integrationId, "/integration_id");
        }

        json::Json document;
        document.setObject();
        document.setString("Wazuh Inc.", "/author");
        document.setString("2025-09-26T10:00:00.000Z", "/date");
        document.setBool(true, "/enabled");
        document.setString(id, "/id");
        document.setString(title, "/title");

        json::Json content;
        content.setObject();
        content.setString("value1", "/key1");
        content.setString("value2", "/key2");
        content.setInt(123, "/key3");
        document.set("/content", content);

        json::Json references;
        references.setArray();
        references.appendString("https://wazuh.com");
        document.set("/references", references);

        payload.set("/document", document);
        kvdb.set("/payload", payload);

        return kvdb;
    }

    std::filesystem::path m_testDbPath;
    std::unique_ptr<CTIStorageDB> m_storage;
};

// Benchmark: Single Integration Storage
static void BM_StoreIntegration(benchmark::State& state)
{
    CTIStorageBenchmark bench;

    for (auto _ : state)
    {
        state.PauseTiming();
        auto integration = bench.createSampleIntegration(
            "integration_" + std::to_string(state.iterations()),
            "Integration " + std::to_string(state.iterations())
        );
        state.ResumeTiming();

        bench.m_storage->storeIntegration(integration);
    }
}

// Benchmark: Single Decoder Storage
static void BM_StoreDecoder(benchmark::State& state)
{
    CTIStorageBenchmark bench;

    for (auto _ : state)
    {
        state.PauseTiming();
        auto decoder = bench.createSampleDecoder(
            "decoder_" + std::to_string(state.iterations()),
            "Decoder " + std::to_string(state.iterations())
        );
        state.ResumeTiming();

        bench.m_storage->storeDecoder(decoder);
    }
}

// Benchmark: Single KVDB Storage
static void BM_StoreKVDB(benchmark::State& state)
{
    CTIStorageBenchmark bench;

    for (auto _ : state)
    {
        state.PauseTiming();
        auto kvdb = bench.createSampleKVDB(
            "kvdb_" + std::to_string(state.iterations()),
            "KVDB " + std::to_string(state.iterations())
        );
        state.ResumeTiming();

        bench.m_storage->storeKVDB(kvdb);
    }
}

// Benchmark: Bulk Load Performance
static void BM_BulkLoad(benchmark::State& state)
{
    const int num_integrations = state.range(0);
    const int decoders_per_integration = 10;
    const int kvdbs_per_integration = 5;

    for (auto _ : state)
    {
        state.PauseTiming();

        // Create fresh storage for each iteration
        CTIStorageBenchmark bench;

        // Prepare data
        std::vector<json::Json> integrations, decoders, kvdbs;

        for (int i = 0; i < num_integrations; ++i)
        {
            std::string integration_id = "integration_" + std::to_string(i);
            std::string integration_title = "Integration " + std::to_string(i);

            auto integration = bench.createSampleIntegration(integration_id, integration_title);
            integrations.push_back(integration);

            // Create decoders for this integration
            for (int d = 0; d < decoders_per_integration; ++d)
            {
                std::string decoder_id = integration_id + "_decoder_" + std::to_string(d);
                std::string decoder_title = integration_title + " Decoder " + std::to_string(d);
                auto decoder = bench.createSampleDecoder(decoder_id, decoder_title, integration_id);
                decoders.push_back(decoder);
            }

            // Create kvdbs for this integration
            for (int k = 0; k < kvdbs_per_integration; ++k)
            {
                std::string kvdb_id = integration_id + "_kvdb_" + std::to_string(k);
                std::string kvdb_title = integration_title + " KVDB " + std::to_string(k);
                auto kvdb = bench.createSampleKVDB(kvdb_id, kvdb_title, integration_id);
                kvdbs.push_back(kvdb);
            }
        }

        state.ResumeTiming();

        // Store all documents
        for (const auto& integration : integrations)
        {
            bench.m_storage->storeIntegration(integration);
        }

        for (const auto& decoder : decoders)
        {
            bench.m_storage->storeDecoder(decoder);
        }

        for (const auto& kvdb : kvdbs)
        {
            bench.m_storage->storeKVDB(kvdb);
        }
    }

    state.SetItemsProcessed(state.iterations() * num_integrations * (1 + decoders_per_integration + kvdbs_per_integration));
}

// Benchmark: Asset Retrieval by Name
static void BM_GetAssetByName(benchmark::State& state)
{
    CTIStorageBenchmark bench;

    // Setup: Store some test data
    for (int i = 0; i < 100; ++i)
    {
        auto integration = bench.createSampleIntegration(
            "integration_" + std::to_string(i),
            "Integration " + std::to_string(i)
        );
        bench.m_storage->storeIntegration(integration);
    }

    int counter = 0;
    for (auto _ : state)
    {
        std::string name = "Integration " + std::to_string(counter % 100);
        auto asset = bench.m_storage->getAsset(base::Name(name), "integration");
        benchmark::DoNotOptimize(asset);
        counter++;
    }
}

// Benchmark: Asset List Retrieval
static void BM_GetAssetList(benchmark::State& state)
{
    CTIStorageBenchmark bench;

    // Setup: Store test data with varying amounts
    int num_assets = state.range(0);
    for (int i = 0; i < num_assets; ++i)
    {
        auto integration = bench.createSampleIntegration(
            "integration_" + std::to_string(i),
            "Integration " + std::to_string(i)
        );
        bench.m_storage->storeIntegration(integration);
    }

    for (auto _ : state)
    {
        auto assets = bench.m_storage->getAssetList("integration");
        benchmark::DoNotOptimize(assets);
    }

    state.SetItemsProcessed(state.iterations() * num_assets);
}

// Register benchmarks
BENCHMARK(BM_StoreIntegration);
BENCHMARK(BM_StoreDecoder);
BENCHMARK(BM_StoreKVDB);

BENCHMARK(BM_BulkLoad)
    ->Arg(10)
    ->Arg(50)
    ->Arg(100)
    ->Unit(benchmark::kMillisecond);

BENCHMARK(BM_GetAssetByName);

BENCHMARK(BM_GetAssetList)
    ->Arg(10)
    ->Arg(50)
    ->Arg(100)
    ->Arg(500)
    ->Unit(benchmark::kMicrosecond);

// BENCHMARK_MAIN() is provided by cm_bench.cpp
