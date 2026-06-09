#include <benchmark/benchmark.h>

#include <string>

#include <base/json.hpp>
#include <rapidjson/document.h>

using namespace json;

// =============================================================================
// Test data: JSON strings of varying sizes and structures
// =============================================================================

static const std::string SMALL_FLAT_JSON = R"({
    "name": "wazuh-agent",
    "id": "001",
    "version": "5.0.0",
    "status": "active",
    "ip": "192.168.1.100"
})";

// --- Documents WITH duplicate keys (for removeDuplicateKeys benchmarks) ---

static const std::string SMALL_WITH_DUPS = R"({
    "name": "wazuh-agent",
    "id": "001",
    "name": "duplicate-name",
    "status": "active",
    "id": "002"
})";

static const std::string MEDIUM_WITH_DUPS = R"({
    "agent": {
        "id": "001",
        "name": "wazuh-agent",
        "id": "002",
        "host": {
            "hostname": "server01",
            "hostname": "server02",
            "os": {
                "name": "Ubuntu",
                "name": "Debian",
                "version": "24.04"
            }
        }
    },
    "event": {
        "kind": "event",
        "kind": "alert",
        "category": ["process"]
    },
    "agent": {"id": "003"}
})";

static const std::string MEDIUM_NESTED_JSON = R"({
    "agent": {
        "id": "001",
        "name": "wazuh-agent",
        "version": "5.0.0",
        "host": {
            "hostname": "server01",
            "os": {
                "name": "Ubuntu",
                "version": "24.04",
                "platform": "linux",
                "arch": "x86_64"
            },
            "ip": ["192.168.1.100", "10.0.0.5"],
            "mac": ["00:11:22:33:44:55"]
        }
    },
    "event": {
        "kind": "event",
        "category": ["process"],
        "type": ["start"],
        "module": "syscheck",
        "dataset": "file"
    },
    "message": "File integrity monitoring event detected",
    "rule": {
        "id": "550",
        "level": 7,
        "description": "Integrity checksum changed"
    }
})";

static const std::string LARGE_DEEPLY_NESTED_JSON = R"({
    "event": {
        "kind": "alert",
        "category": ["intrusion_detection"],
        "type": ["info"],
        "severity": 3,
        "created": "2026-01-15T10:30:00.000Z",
        "provider": "wazuh",
        "module": "syscheck"
    },
    "agent": {
        "id": "003",
        "name": "prod-server-03",
        "type": "endpoint",
        "version": "5.0.0",
        "host": {
            "hostname": "prod-server-03",
            "architecture": "x86_64",
            "os": {
                "family": "debian",
                "name": "Ubuntu",
                "version": "24.04.1 LTS",
                "kernel": "6.8.0-45-generic",
                "platform": "linux",
                "type": "linux",
                "codename": "noble"
            },
            "ip": ["10.0.1.50", "172.16.0.50", "fd00::50"],
            "mac": ["00:11:22:33:44:55", "00:11:22:33:44:56"],
            "geo": {
                "city_name": "San Francisco",
                "country_name": "United States",
                "location": {
                    "lat": 37.7749,
                    "lon": -122.4194
                },
                "region_name": "California"
            }
        }
    },
    "source": {
        "ip": "203.0.113.50",
        "port": 44312,
        "geo": {
            "city_name": "Moscow",
            "country_name": "Russia",
            "continent_name": "Europe",
            "location": {
                "lat": 55.7558,
                "lon": 37.6173
            }
        }
    },
    "destination": {
        "ip": "10.0.1.50",
        "port": 22,
        "service": "ssh"
    },
    "rule": {
        "id": "5712",
        "level": 10,
        "description": "SSHD brute force trying to get access to the system",
        "groups": ["syslog", "sshd", "authentication_failures"],
        "mitre": {
            "id": ["T1110"],
            "tactic": ["Credential Access"],
            "technique": ["Brute Force"]
        },
        "pci_dss": ["10.2.4", "10.2.5", "11.4"],
        "gdpr": ["IV_35.7.d", "IV_32.2"],
        "hipaa": ["164.312.b"]
    },
    "vulnerability": {
        "id": "CVE-2024-1234",
        "severity": "high",
        "score": {
            "base": 8.1,
            "version": "3.1"
        },
        "category": ["remote_code_execution"],
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    },
    "file": {
        "path": "/etc/shadow",
        "hash": {
            "sha256": "abc123def456789012345678901234567890123456789012345678901234abcd",
            "md5": "d41d8cd98f00b204e9800998ecf8427e"
        },
        "owner": "root",
        "group": "shadow",
        "mode": "0640",
        "size": 1542,
        "inode": 262147
    }
})";

// Generate a flat JSON with N unique keys
static std::string generateFlatJson(size_t numKeys)
{
    std::string json = "{";
    for (size_t i = 0; i < numKeys; ++i)
    {
        if (i > 0)
            json += ",";
        json += "\"key_" + std::to_string(i) + "\":\"value_" + std::to_string(i) + "\"";
    }
    json += "}";
    return json;
}

// Generate a flat JSON where a fraction of keys are duplicates
static std::string generateFlatJsonWithDups(size_t numKeys, size_t numDups)
{
    std::string json = "{";
    for (size_t i = 0; i < numKeys; ++i)
    {
        if (i > 0)
            json += ",";
        json += "\"key_" + std::to_string(i) + "\":\"value_" + std::to_string(i) + "\"";
    }
    // Append duplicate keys at the end
    for (size_t i = 0; i < numDups; ++i)
    {
        json += ",\"key_" + std::to_string(i) + "\":\"dup_value_" + std::to_string(i) + "\"";
    }
    json += "}";
    return json;
}

// Generate a JSON with arrays of objects
static std::string generateArrayJson(size_t numElements)
{
    std::string json = R"({"data":[)";
    for (size_t i = 0; i < numElements; ++i)
    {
        if (i > 0)
            json += ",";
        json += R"({"id":)" + std::to_string(i) + R"(,"name":"item_)" + std::to_string(i)
                + R"(","active":true,"score":)" + std::to_string(i * 1.5) + "}";
    }
    json += "]}";
    return json;
}

static const std::string LARGE_FLAT_JSON = generateFlatJson(100);
static const std::string ARRAY_JSON = generateArrayJson(50);
static const std::string LARGE_FLAT_WITH_DUPS = generateFlatJsonWithDups(100, 20);

// =============================================================================
// Group A: JSON construction (parse only — constructors no longer check dups)
// =============================================================================

static void BM_JsonConstruction_SmallFlat(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(SMALL_FLAT_JSON);
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(SMALL_FLAT_JSON.size()));
}
BENCHMARK(BM_JsonConstruction_SmallFlat);

static void BM_JsonConstruction_MediumNested(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(MEDIUM_NESTED_JSON);
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(MEDIUM_NESTED_JSON.size()));
}
BENCHMARK(BM_JsonConstruction_MediumNested);

static void BM_JsonConstruction_LargeFlat(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_FLAT_JSON);
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(LARGE_FLAT_JSON.size()));
}
BENCHMARK(BM_JsonConstruction_LargeFlat);

static void BM_JsonConstruction_LargeDeeplyNested(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_DEEPLY_NESTED_JSON);
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(LARGE_DEEPLY_NESTED_JSON.size()));
}
BENCHMARK(BM_JsonConstruction_LargeDeeplyNested);

static void BM_JsonConstruction_WithArrays(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(ARRAY_JSON);
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(ARRAY_JSON.size()));
}
BENCHMARK(BM_JsonConstruction_WithArrays);

// =============================================================================
// Group B: checkDuplicateKeys in isolation (detection only, no removal)
// Measures the traversal cost of detecting duplicate keys.
// =============================================================================

static void BM_CheckDuplicateKeys_SmallFlat(benchmark::State& state)
{
    Json json(SMALL_FLAT_JSON);
    for (auto _ : state)
    {
        auto result = json.checkDuplicateKeys();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CheckDuplicateKeys_SmallFlat);

static void BM_CheckDuplicateKeys_MediumNested(benchmark::State& state)
{
    Json json(MEDIUM_NESTED_JSON);
    for (auto _ : state)
    {
        auto result = json.checkDuplicateKeys();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CheckDuplicateKeys_MediumNested);

static void BM_CheckDuplicateKeys_LargeFlat(benchmark::State& state)
{
    Json json(LARGE_FLAT_JSON);
    for (auto _ : state)
    {
        auto result = json.checkDuplicateKeys();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CheckDuplicateKeys_LargeFlat);

static void BM_CheckDuplicateKeys_LargeDeeplyNested(benchmark::State& state)
{
    Json json(LARGE_DEEPLY_NESTED_JSON);
    for (auto _ : state)
    {
        auto result = json.checkDuplicateKeys();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CheckDuplicateKeys_LargeDeeplyNested);

static void BM_CheckDuplicateKeys_WithArrays(benchmark::State& state)
{
    Json json(ARRAY_JSON);
    for (auto _ : state)
    {
        auto result = json.checkDuplicateKeys();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_CheckDuplicateKeys_WithArrays);

// =============================================================================
// Group C: removeDuplicateKeys in isolation
// Measures the cost of finding AND removing duplicate keys.
// Each iteration re-parses to restore the duplicates before removing them.
// =============================================================================

static void BM_RemoveDuplicateKeys_SmallNoDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(SMALL_FLAT_JSON);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RemoveDuplicateKeys_SmallNoDups);

static void BM_RemoveDuplicateKeys_SmallWithDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(SMALL_WITH_DUPS);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RemoveDuplicateKeys_SmallWithDups);

static void BM_RemoveDuplicateKeys_MediumWithDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(MEDIUM_WITH_DUPS);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RemoveDuplicateKeys_MediumWithDups);

static void BM_RemoveDuplicateKeys_LargeFlatNoDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_FLAT_JSON);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RemoveDuplicateKeys_LargeFlatNoDups);

static void BM_RemoveDuplicateKeys_LargeFlatWithDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_FLAT_WITH_DUPS);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RemoveDuplicateKeys_LargeFlatWithDups);

static void BM_RemoveDuplicateKeys_LargeDeeplyNested(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_DEEPLY_NESTED_JSON);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_RemoveDuplicateKeys_LargeDeeplyNested);

// =============================================================================
// Group D: Full pipeline — construct + checkDuplicateKeys + removeDuplicateKeys
// Simulates the pattern used by fileDriver (validate before writing to disk).
// =============================================================================

static void BM_FullPipeline_SmallFlat(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(SMALL_FLAT_JSON);
        auto error = json.checkDuplicateKeys();
        if (error)
        {
            json.removeDuplicateKeys();
        }
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(SMALL_FLAT_JSON.size()));
}
BENCHMARK(BM_FullPipeline_SmallFlat);

static void BM_FullPipeline_SmallWithDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(SMALL_WITH_DUPS);
        auto error = json.checkDuplicateKeys();
        if (error)
        {
            json.removeDuplicateKeys();
        }
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(SMALL_WITH_DUPS.size()));
}
BENCHMARK(BM_FullPipeline_SmallWithDups);

static void BM_FullPipeline_LargeFlatNoDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_FLAT_JSON);
        auto error = json.checkDuplicateKeys();
        if (error)
        {
            json.removeDuplicateKeys();
        }
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(LARGE_FLAT_JSON.size()));
}
BENCHMARK(BM_FullPipeline_LargeFlatNoDups);

static void BM_FullPipeline_LargeFlatWithDups(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_FLAT_WITH_DUPS);
        auto error = json.checkDuplicateKeys();
        if (error)
        {
            json.removeDuplicateKeys();
        }
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(LARGE_FLAT_WITH_DUPS.size()));
}
BENCHMARK(BM_FullPipeline_LargeFlatWithDups);

static void BM_FullPipeline_LargeDeeplyNested(benchmark::State& state)
{
    for (auto _ : state)
    {
        Json json(LARGE_DEEPLY_NESTED_JSON);
        auto error = json.checkDuplicateKeys();
        if (error)
        {
            json.removeDuplicateKeys();
        }
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(LARGE_DEEPLY_NESTED_JSON.size()));
}
BENCHMARK(BM_FullPipeline_LargeDeeplyNested);

// =============================================================================
// Group E: Scaling — compare operations with increasing number of flat keys
// =============================================================================

// E1: Construction only (parse) — scales with document size
static void BM_Construction_Scaling(benchmark::State& state)
{
    const auto numKeys = static_cast<size_t>(state.range(0));
    const std::string jsonStr = generateFlatJson(numKeys);

    for (auto _ : state)
    {
        Json json(jsonStr);
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(jsonStr.size()));
    state.SetLabel(std::to_string(numKeys) + " keys");
}
BENCHMARK(BM_Construction_Scaling)->RangeMultiplier(2)->Range(8, 1024);

// E2: checkDuplicateKeys — detection cost scales with key count (no dups)
static void BM_CheckDuplicateKeys_Scaling(benchmark::State& state)
{
    const auto numKeys = static_cast<size_t>(state.range(0));
    const std::string jsonStr = generateFlatJson(numKeys);
    Json json(jsonStr);

    for (auto _ : state)
    {
        auto result = json.checkDuplicateKeys();
        benchmark::DoNotOptimize(result);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetLabel(std::to_string(numKeys) + " keys");
}
BENCHMARK(BM_CheckDuplicateKeys_Scaling)->RangeMultiplier(2)->Range(8, 1024);

// E3: removeDuplicateKeys on clean docs (no dups to remove)
static void BM_RemoveDuplicateKeys_ScalingNoDups(benchmark::State& state)
{
    const auto numKeys = static_cast<size_t>(state.range(0));
    const std::string jsonStr = generateFlatJson(numKeys);

    for (auto _ : state)
    {
        Json json(jsonStr);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetLabel(std::to_string(numKeys) + " keys");
}
BENCHMARK(BM_RemoveDuplicateKeys_ScalingNoDups)->RangeMultiplier(2)->Range(8, 1024);

// E4: removeDuplicateKeys with 20% duplicate keys
static void BM_RemoveDuplicateKeys_ScalingWithDups(benchmark::State& state)
{
    const auto numKeys = static_cast<size_t>(state.range(0));
    const size_t numDups = numKeys / 5; // 20% duplicates
    const std::string jsonStr = generateFlatJsonWithDups(numKeys, numDups);

    for (auto _ : state)
    {
        Json json(jsonStr);
        auto removed = json.removeDuplicateKeys();
        benchmark::DoNotOptimize(removed);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetLabel(std::to_string(numKeys) + " keys + " + std::to_string(numDups) + " dups");
}
BENCHMARK(BM_RemoveDuplicateKeys_ScalingWithDups)->RangeMultiplier(2)->Range(8, 1024);

// E5: Full pipeline scaling (construct + check + conditional remove)
static void BM_FullPipeline_ScalingWithDups(benchmark::State& state)
{
    const auto numKeys = static_cast<size_t>(state.range(0));
    const size_t numDups = numKeys / 5;
    const std::string jsonStr = generateFlatJsonWithDups(numKeys, numDups);

    for (auto _ : state)
    {
        Json json(jsonStr);
        auto error = json.checkDuplicateKeys();
        if (error)
        {
            json.removeDuplicateKeys();
        }
        benchmark::DoNotOptimize(json);
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(jsonStr.size()));
    state.SetLabel(std::to_string(numKeys) + " keys + " + std::to_string(numDups) + " dups");
}
BENCHMARK(BM_FullPipeline_ScalingWithDups)->RangeMultiplier(2)->Range(8, 1024);
