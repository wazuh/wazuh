#include <gtest/gtest.h>

#include <opentelemetry/context/runtime_context.h>
#include <opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h>
#include <opentelemetry/sdk/metrics/meter.h>
#include <opentelemetry/sdk/metrics/meter_context.h>
#include <opentelemetry/sdk/metrics/meter_provider.h>

#include <base/behaviour.hpp>
#include <base/logging.hpp>
#include <indexerConnector/mockiconnector.hpp>

#include "exporter/indexerMetricsExporter.hpp"
#include "metrics/ot.hpp"

using namespace base::test;
using namespace metrics;

TEST(IndexerMetricsExporter, Instantiate)
{
    ASSERT_THROW(auto exporter = metrics::IndexerMetricsExporter(nullptr), std::runtime_error);
    auto indexerConnector = std::make_shared<indexerconnector::mocks::MockIConnector>();
    ASSERT_NO_THROW(auto exporter = metrics::IndexerMetricsExporter(indexerConnector));
}

TEST(IndexerMetricsExporter, GetAggregationTemporality)
{
    auto indexerConnector = std::make_shared<indexerconnector::mocks::MockIConnector>();
    metrics::IndexerMetricsExporter exporter(indexerConnector);

    auto types = {opentelemetry::sdk::metrics::InstrumentType::kCounter,
                  opentelemetry::sdk::metrics::InstrumentType::kHistogram,
                  opentelemetry::sdk::metrics::InstrumentType::kUpDownCounter,
                  opentelemetry::sdk::metrics::InstrumentType::kObservableCounter,
                  opentelemetry::sdk::metrics::InstrumentType::kObservableGauge,
                  opentelemetry::sdk::metrics::InstrumentType::kObservableUpDownCounter};

    for (auto type : types)
    {
        ASSERT_EQ(exporter.GetAggregationTemporality(type),
                  opentelemetry::sdk::metrics::AggregationTemporality::kCumulative);
    }
}

TEST(IndexerMetricsExporter, ForceFlush)
{
    auto indexerConnector = std::make_shared<indexerconnector::mocks::MockIConnector>();
    metrics::IndexerMetricsExporter exporter(indexerConnector);

    ASSERT_TRUE(exporter.ForceFlush(std::chrono::microseconds(500)));
}

TEST(IndexerMetricsExporter, Shutdown)
{
    auto indexerConnector = std::make_shared<indexerconnector::mocks::MockIConnector>();
    metrics::IndexerMetricsExporter exporter(indexerConnector);

    ASSERT_TRUE(exporter.Shutdown(std::chrono::microseconds(500)));
}

namespace exporttest
{
using SuccessExpected = InnerExpected<None, std::shared_ptr<indexerconnector::mocks::MockIConnector>, json::Json>;
using FailureExpected = InnerExpected<None, std::shared_ptr<indexerconnector::mocks::MockIConnector>, json::Json>;
using Expc = Expected<SuccessExpected, FailureExpected>;
auto SUCCESS = Expc::success();
auto FAILURE = Expc::failure();

using ExportT = std::tuple<std::function<void(std::shared_ptr<ot::MeterProvider>)>, Expc>;

class IndexerMetricsExportTest : public ::testing::TestWithParam<ExportT>
{
protected:
    std::shared_ptr<indexerconnector::mocks::MockIConnector> m_indexerConnector;
    std::shared_ptr<ot::MeterProvider> m_provider;

public:
    void SetUp() override
    {
        logging::testInit();
        m_indexerConnector = std::make_shared<indexerconnector::mocks::MockIConnector>();

        // Generate test opentelemetry pipeline
        // Exporter
        auto exporter = std::make_unique<metrics::IndexerMetricsExporter>(m_indexerConnector);

        // Reader
        auto readerOptions = opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions();
        readerOptions.export_interval_millis = std::chrono::milliseconds(500);
        readerOptions.export_timeout_millis = std::chrono::milliseconds(300);
        auto reader = std::make_shared<ot::PeriodicExportingMetricReader>(
            std::unique_ptr<ot::PushMetricExporter>(std::move(exporter)), readerOptions);

        // Provider
        m_provider = std::make_shared<ot::MeterProvider>();
        m_provider->AddMetricReader(reader);
    }

    json::Json getExpectedJson() const
    {
        json::Json expectedJson;

        expectedJson.setString("ADD", "/operation");
        expectedJson.setObject("/data");
        expectedJson.setString("test", "/data/name");
        expectedJson.setString("", "/data/schema");
        expectedJson.setString("", "/data/version");

        return expectedJson;
    }
};

TEST_P(IndexerMetricsExportTest, Export)
{
    auto [metricsLambda, expected] = GetParam();

    auto expectedJson = getExpectedJson();
    if (expected)
    {
        expected.succCase()(m_indexerConnector, expectedJson);
    }
    else
    {
        expected.failCase()(m_indexerConnector, expectedJson);
    }

    // Generate metrics
    metricsLambda(m_provider);

    // Sleep 2 cycles to allow the exporter to export the metrics
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

json::Json getBoundaries()
{
    json::Json boundaries;
    boundaries.setArray();
    json::Json bound;
    bound.setDouble(0.0);
    boundaries.appendJson(bound);
    bound.setDouble(5.0);
    boundaries.appendJson(bound);
    bound.setDouble(10.0);
    boundaries.appendJson(bound);
    bound.setDouble(25.0);
    boundaries.appendJson(bound);
    bound.setDouble(50.0);
    boundaries.appendJson(bound);
    bound.setDouble(75.0);
    boundaries.appendJson(bound);
    bound.setDouble(100.0);
    boundaries.appendJson(bound);
    bound.setDouble(250.0);
    boundaries.appendJson(bound);
    bound.setDouble(500.0);
    boundaries.appendJson(bound);
    bound.setDouble(750.0);
    boundaries.appendJson(bound);
    bound.setDouble(1000.0);
    boundaries.appendJson(bound);
    bound.setDouble(2500.0);
    boundaries.appendJson(bound);
    bound.setDouble(5000.0);
    boundaries.appendJson(bound);
    bound.setDouble(7500.0);
    boundaries.appendJson(bound);
    bound.setDouble(10000.0);
    boundaries.appendJson(bound);

    return boundaries;
}

json::Json getCounts()
{
    json::Json count;
    json::Json counts;
    count.setInt64(0);
    counts.appendJson(count);
    count.setInt64(1);
    counts.appendJson(count);
    for (auto i = 0; i < 14; i++)
    {
        count.setInt64(0);
        counts.appendJson(count);
    }
    return counts;
}

INSTANTIATE_TEST_SUITE_P(
    // Test suite name
    Metrics,
    IndexerMetricsExportTest,
    ::testing::Values(
        // IndexerConnector throws exception
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto counter = meter->CreateUInt64Counter("counter");
                auto context = ot::context::RuntimeContext::GetCurrent();
                counter->Add(1, context);
            },
            FAILURE(
                [](auto connectorMock, auto)
                {
                    EXPECT_CALL(*connectorMock, publish(testing::_))
                        .WillRepeatedly(testing::Throw(std::runtime_error("Mock error")));

                    return None {};
                })),
        // Counter
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto counter = meter->CreateUInt64Counter("counterInt");
                auto context = ot::context::RuntimeContext::GetCurrent();
                counter->Add(1, context);
            },
            SUCCESS(
                [](auto connectorMock, auto expectedJson)
                {
                    expectedJson.setArray("/data/metrics");
                    json::Json expectedCounter;
                    expectedCounter.setString("counterInt", "/name");
                    expectedCounter.setString("", "/description");
                    expectedCounter.setString("", "/unit");

                    json::Json expectedPoints;
                    expectedPoints.setBool(true, "/isMonotonic");
                    expectedPoints.setInt64(1, "/value");

                    expectedCounter.appendJson(expectedPoints, "/points");
                    expectedJson.appendJson(expectedCounter, "/data/metrics");

                    auto expectedString = expectedJson.str();
                    EXPECT_CALL(*connectorMock, publish(expectedString)).Times(testing::AtLeast(1));

                    return None {};
                })),
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto counter = meter->CreateDoubleCounter("counterDouble");
                auto context = ot::context::RuntimeContext::GetCurrent();
                counter->Add(1.5, context);
            },
            SUCCESS(
                [](auto connectorMock, auto expectedJson)
                {
                    expectedJson.setArray("/data/metrics");
                    json::Json expectedCounter;
                    expectedCounter.setString("counterDouble", "/name");
                    expectedCounter.setString("", "/description");
                    expectedCounter.setString("", "/unit");

                    json::Json expectedPoints;
                    expectedPoints.setBool(true, "/isMonotonic");
                    expectedPoints.setDouble(1.5, "/value");

                    expectedCounter.appendJson(expectedPoints, "/points");
                    expectedJson.appendJson(expectedCounter, "/data/metrics");

                    auto expectedString = expectedJson.str();
                    EXPECT_CALL(*connectorMock, publish(expectedString)).Times(testing::AtLeast(1));

                    return None {};
                })),
        // Histogram
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto histogram = meter->CreateUInt64Histogram("histogram");
                auto context = ot::context::RuntimeContext::GetCurrent();
                histogram->Record(1, context);
            },
            SUCCESS(
                [](auto connectorMock, auto expectedJson)
                {
                    expectedJson.setArray("/data/metrics");
                    json::Json expectedHistogram;
                    expectedHistogram.setString("histogram", "/name");
                    expectedHistogram.setString("", "/description");
                    expectedHistogram.setString("", "/unit");

                    json::Json expectedPoints;
                    expectedPoints.setInt64(1, "/count");
                    expectedPoints.setInt64(1, "/min");
                    expectedPoints.setInt64(1, "/max");
                    expectedPoints.setInt64(1, "/sum");

                    expectedPoints.setArray("/boundaries");
                    auto boundaries = getBoundaries();
                    expectedPoints.appendJson(boundaries, "/boundaries");

                    expectedPoints.setArray("/counts");
                    auto counts = getCounts();
                    expectedPoints.appendJson(counts, "/counts");

                    expectedHistogram.appendJson(expectedPoints, "/points");
                    expectedJson.appendJson(expectedHistogram, "/data/metrics");

                    auto expectedString = expectedJson.str();
                    EXPECT_CALL(*connectorMock, publish(expectedString)).Times(testing::AtLeast(1));

                    return None {};
                })),
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto histogram = meter->CreateDoubleHistogram("histogram");
                auto context = ot::context::RuntimeContext::GetCurrent();
                histogram->Record(1.5, context);
            },
            SUCCESS(
                [](auto connectorMock, auto expectedJson)
                {
                    expectedJson.setArray("/data/metrics");
                    json::Json expectedHistogram;
                    expectedHistogram.setString("histogram", "/name");
                    expectedHistogram.setString("", "/description");
                    expectedHistogram.setString("", "/unit");

                    json::Json expectedPoints;
                    expectedPoints.setInt64(1, "/count");
                    expectedPoints.setDouble(1.5, "/min");
                    expectedPoints.setDouble(1.5, "/max");
                    expectedPoints.setDouble(1.5, "/sum");

                    expectedPoints.setArray("/boundaries");
                    auto boundaries = getBoundaries();
                    expectedPoints.appendJson(boundaries, "/boundaries");

                    expectedPoints.setArray("/counts");
                    auto counts = getCounts();
                    expectedPoints.appendJson(counts, "/counts");

                    expectedHistogram.appendJson(expectedPoints, "/points");
                    expectedJson.appendJson(expectedHistogram, "/data/metrics");

                    auto expectedString = expectedJson.str();
                    EXPECT_CALL(*connectorMock, publish(expectedString)).Times(testing::AtLeast(1));

                    return None {};
                })),
        // UpDownCounter
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto upDownCounter = meter->CreateInt64UpDownCounter("upDownCounter");
                auto context = ot::context::RuntimeContext::GetCurrent();
                upDownCounter->Add(1, context);
            },
            SUCCESS(
                [](auto connectorMock, auto expectedJson)
                {
                    expectedJson.setArray("/data/metrics");
                    json::Json expectedUpDownCounter;
                    expectedUpDownCounter.setString("upDownCounter", "/name");
                    expectedUpDownCounter.setString("", "/description");
                    expectedUpDownCounter.setString("", "/unit");

                    json::Json expectedPoints;
                    expectedPoints.setInt64(1, "/value");

                    expectedUpDownCounter.appendJson(expectedPoints, "/points");
                    expectedJson.appendJson(expectedUpDownCounter, "/data/metrics");

                    auto expectedString = expectedJson.str();
                    EXPECT_CALL(*connectorMock, publish(expectedString)).Times(testing::AtLeast(1));

                    return None {};
                })),
        ExportT(
            [](auto provider)
            {
                auto meter = provider->GetMeter("test");
                auto upDownCounter = meter->CreateDoubleUpDownCounter("upDownCounter");
                auto context = ot::context::RuntimeContext::GetCurrent();
                upDownCounter->Add(1.5, context);
            },
            SUCCESS(
                [](auto connectorMock, auto expectedJson)
                {
                    expectedJson.setArray("/data/metrics");
                    json::Json expectedUpDownCounter;
                    expectedUpDownCounter.setString("upDownCounter", "/name");
                    expectedUpDownCounter.setString("", "/description");
                    expectedUpDownCounter.setString("", "/unit");

                    json::Json expectedPoints;
                    expectedPoints.setDouble(1.5, "/value");

                    expectedUpDownCounter.appendJson(expectedPoints, "/points");
                    expectedJson.appendJson(expectedUpDownCounter, "/data/metrics");

                    auto expectedString = expectedJson.str();
                    EXPECT_CALL(*connectorMock, publish(expectedString)).Times(testing::AtLeast(1));

                    return None {};
                }))));

} // namespace exporttest
