#include <benchmark/benchmark.h>

#include <memory>
#include <string>
#include <vector>

#include <base/baseTypes.hpp>
#include <base/expression.hpp>
#include <base/json.hpp>
#include <base/result.hpp>
#include <geo/ilocator.hpp>
#include <geo/imanager.hpp>

#include "builders/enrichment/enrichment.hpp"

namespace
{

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight stub locators for benchmarking (no gmock overhead)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Stub City locator that returns pre-canned geo data for a known IP.
 */
class StubCityLocator : public geo::ILocator
{
public:
    geo::Result<std::string> getString(const std::string& ip, const DotPath& path) override
    {
        if (ip != "1.2.3.4")
            return geo::ErrorCode::IP_NOT_FOUND;

        const auto p = path.str();
        if (p == "city.names.en")
            return std::string {"London"};
        if (p == "continent.code")
            return std::string {"EU"};
        if (p == "continent.names.en")
            return std::string {"Europe"};
        if (p == "country.iso_code")
            return std::string {"GB"};
        if (p == "country.names.en")
            return std::string {"United Kingdom"};
        if (p == "postal.code")
            return std::string {"EC1A"};
        if (p == "location.time_zone")
            return std::string {"Europe/London"};
        if (p == "subdivisions.0.iso_code")
            return std::string {"ENG"};
        if (p == "subdivisions.0.names.en")
            return std::string {"England"};

        return geo::ErrorCode::DATA_ENTRY_EMPTY;
    }

    geo::Result<uint32_t> getUint32(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::DATA_TYPE_MISMATCH;
    }

    geo::Result<double> getDouble(const std::string& ip, const DotPath& path) override
    {
        if (ip != "1.2.3.4")
            return geo::ErrorCode::IP_NOT_FOUND;

        const auto p = path.str();
        if (p == "location.latitude")
            return 51.5074;
        if (p == "location.longitude")
            return -0.1278;

        return geo::ErrorCode::DATA_ENTRY_EMPTY;
    }

    geo::Result<json::Json> getAsJson(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::DATA_TYPE_MISMATCH;
    }

    geo::Result<json::Json> getAll(const std::string& /*ip*/) override { return geo::ErrorCode::DATA_TYPE_MISMATCH; }
};

/**
 * @brief Stub ASN locator that returns pre-canned AS data for a known IP.
 */
class StubAsnLocator : public geo::ILocator
{
public:
    geo::Result<std::string> getString(const std::string& ip, const DotPath& path) override
    {
        if (ip != "1.2.3.4")
            return geo::ErrorCode::IP_NOT_FOUND;

        if (path.str() == "autonomous_system_organization")
            return std::string {"Example ISP"};

        return geo::ErrorCode::DATA_ENTRY_EMPTY;
    }

    geo::Result<uint32_t> getUint32(const std::string& ip, const DotPath& path) override
    {
        if (ip != "1.2.3.4")
            return geo::ErrorCode::IP_NOT_FOUND;

        if (path.str() == "autonomous_system_number")
            return uint32_t {12345};

        return geo::ErrorCode::DATA_ENTRY_EMPTY;
    }

    geo::Result<double> getDouble(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::DATA_TYPE_MISMATCH_DOUBLE;
    }

    geo::Result<json::Json> getAsJson(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::DATA_TYPE_MISMATCH;
    }

    geo::Result<json::Json> getAll(const std::string& /*ip*/) override { return geo::ErrorCode::DATA_TYPE_MISMATCH; }
};

/**
 * @brief Stub locator that always returns errors (no data for any IP).
 */
class StubEmptyLocator : public geo::ILocator
{
public:
    geo::Result<std::string> getString(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::IP_NOT_FOUND;
    }
    geo::Result<uint32_t> getUint32(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::IP_NOT_FOUND;
    }
    geo::Result<double> getDouble(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::IP_NOT_FOUND;
    }
    geo::Result<json::Json> getAsJson(const std::string& /*ip*/, const DotPath& /*path*/) override
    {
        return geo::ErrorCode::IP_NOT_FOUND;
    }
    geo::Result<json::Json> getAll(const std::string& /*ip*/) override { return geo::ErrorCode::IP_NOT_FOUND; }
};

/**
 * @brief Stub GeoIP manager that hands out the given locators.
 */
class StubGeoManager : public geo::IManager
{
    std::shared_ptr<geo::ILocator> m_city;
    std::shared_ptr<geo::ILocator> m_asn;

public:
    StubGeoManager(std::shared_ptr<geo::ILocator> city, std::shared_ptr<geo::ILocator> asn)
        : m_city(std::move(city))
        , m_asn(std::move(asn))
    {
    }

    std::vector<geo::DbInfo> listDbs() const override { return {}; }

    geo::Result<std::shared_ptr<geo::ILocator>> getLocator(geo::Type type) const override
    {
        if (type == geo::Type::CITY)
            return m_city;
        if (type == geo::Type::ASN)
            return m_asn;
        return geo::ErrorCode::DB_TYPE_NOT_AVAILABLE;
    }

    void remoteUpsert(const std::string& /*manifestUrl*/,
                      const std::string& /*cityPath*/,
                      const std::string& /*asnPath*/) override
    {
    }

    void requestShutdown() override {}
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create a mapping config JSON document
// ─────────────────────────────────────────────────────────────────────────────

json::Json makeMappingConfig(bool withGeo, bool withAs)
{
    std::string inner = "{";
    bool first = true;
    if (withGeo)
    {
        inner += R"("geo_field": "source.geo")";
        first = false;
    }
    if (withAs)
    {
        if (!first)
            inner += ",";
        inner += R"("as_field": "source.as")";
    }
    inner += "}";

    auto doc = fmt::format(R"({{"source.ip": {}}})", inner);
    return json::Json {doc.c_str()};
}

/**
 * @brief Helper: build the enrichment expression once, then benchmark applying it.
 */
base::Expression buildEnrichmentExpr(const std::shared_ptr<geo::IManager>& mgr, const json::Json& configDoc, bool isTestMode)
{
    auto enrichBuilder = builder::builders::enrichment::getGeoEnrichmentBuilder(mgr, configDoc);
    auto [expr, name] = enrichBuilder(isTestMode);
    return expr;
}

/**
 * @brief Create a sample event JSON with the given IP at "source.ip".
 */
base::Event makeEvent(const std::string& ip)
{
    auto ev = std::make_shared<json::Json>(
        fmt::format(R"({{"source":{{"ip":"{}"}}, "event":{{"original":"test"}}}})", ip).c_str());
    return ev;
}

/**
 * @brief Create a sample event JSON with no IP field.
 */
base::Event makeEventNoIp()
{
    auto ev = std::make_shared<json::Json>(R"({"source":{}, "event":{"original":"test"}})");
    return ev;
}

// ─────────────────────────────────────────────────────────────────────────────
// Expression evaluator (mirrors the one used in builder component tests)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Walk the expression graph and execute every Term on the event.
 *
 * This mirrors the evalExpression helper used in builder component tests.
 * It handles Term, Chain, Implication, And, Or and Broadcast node types.
 */
bool evalExpression(const base::Expression& expression, const base::Event& event)
{
    if (expression == nullptr)
        return true;

    if (expression->isTerm())
    {
        auto term = expression->getPtr<base::Term<base::EngineOp>>();
        return term->getFn()(event).success();
    }

    if (expression->isChain())
    {
        auto op = expression->getPtr<base::Chain>();
        for (auto& operand : op->getOperands()) evalExpression(operand, event);
        return true;
    }

    if (expression->isImplication())
    {
        auto op = expression->getPtr<base::Implication>();
        if (evalExpression(op->getOperands()[0], event))
            return evalExpression(op->getOperands()[1], event);
        return false;
    }

    if (expression->isAnd())
    {
        auto op = expression->getPtr<base::And>();
        for (auto& operand : op->getOperands())
        {
            if (!evalExpression(operand, event))
                return false;
        }
        return true;
    }

    if (expression->isOr())
    {
        auto op = expression->getPtr<base::Or>();
        for (auto& operand : op->getOperands())
        {
            if (evalExpression(operand, event))
                return true;
        }
        return false;
    }

    if (expression->isBroadcast())
    {
        auto op = expression->getPtr<base::Broadcast>();
        for (auto& operand : op->getOperands()) evalExpression(operand, event);
        return true;
    }

    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Benchmark: Geo + AS enrichment with a known IP (both succeed), isTestMode OFF.
 */
static void BM_GeoAS_KnownIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev = makeEvent("1.2.3.4");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_KnownIP_NoTrace);

/**
 * Benchmark: Geo + AS enrichment with a known IP (both succeed), isTestMode ON.
 */
static void BM_GeoAS_KnownIP_Trace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, true);

    for (auto _ : state)
    {
        auto ev = makeEvent("1.2.3.4");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_KnownIP_Trace);

/**
 * Benchmark: Geo-only enrichment with a known IP, isTestMode OFF.
 */
static void BM_GeoOnly_KnownIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, false);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev = makeEvent("1.2.3.4");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoOnly_KnownIP_NoTrace);

/**
 * Benchmark: AS-only enrichment with a known IP, isTestMode OFF.
 */
static void BM_ASOnly_KnownIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(false, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev = makeEvent("1.2.3.4");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_ASOnly_KnownIP_NoTrace);

/**
 * Benchmark: Geo + AS enrichment with an unknown IP (no data), isTestMode OFF.
 */
static void BM_GeoAS_UnknownIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev = makeEvent("9.9.9.9");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_UnknownIP_NoTrace);

/**
 * Benchmark: Geo + AS enrichment with an unknown IP (no data), isTestMode ON.
 */
static void BM_GeoAS_UnknownIP_Trace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, true);

    for (auto _ : state)
    {
        auto ev = makeEvent("9.9.9.9");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_UnknownIP_Trace);

/**
 * Benchmark: Missing IP field in event (early exit path), isTestMode OFF.
 */
static void BM_GeoAS_MissingIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev = makeEventNoIp();
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_MissingIP_NoTrace);

/**
 * Benchmark: Missing IP field in event (early exit path), isTestMode ON.
 */
static void BM_GeoAS_MissingIP_Trace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, true);

    for (auto _ : state)
    {
        auto ev = makeEventNoIp();
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_MissingIP_Trace);

/**
 * Benchmark: Empty locators (DB not available scenario), known IP, isTestMode OFF.
 */
static void BM_EmptyLocators_KnownIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubEmptyLocator>(), std::make_shared<StubEmptyLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev = makeEvent("1.2.3.4");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_EmptyLocators_KnownIP_NoTrace);

/**
 * Benchmark: Geo + AS enrichment with a known IP stored as array, isTestMode OFF.
 * Tests the fallback path: event->getString(path + "/0")
 */
static void BM_GeoAS_ArrayIP_NoTrace(benchmark::State& state)
{
    auto mgr =
        std::make_shared<StubGeoManager>(std::make_shared<StubCityLocator>(), std::make_shared<StubAsnLocator>());
    auto configDoc = makeMappingConfig(true, true);
    auto expr = buildEnrichmentExpr(mgr, configDoc, false);

    for (auto _ : state)
    {
        auto ev =
            std::make_shared<json::Json>(R"({"source":{"ip":["1.2.3.4","5.6.7.8"]}, "event":{"original":"test"}})");
        auto result = evalExpression(expr, ev);
        benchmark::DoNotOptimize(result);
        benchmark::DoNotOptimize(ev);
    }
    state.SetItemsProcessed(state.iterations());
}
BENCHMARK(BM_GeoAS_ArrayIP_NoTrace);

} // anonymous namespace

BENCHMARK_MAIN();
