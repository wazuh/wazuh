#include <gtest/gtest.h>

#include <metrics/dataHubExporter.hpp>
#include <metrics/metricsScope.hpp>

#include "mocks/mockDataHubExporter.hpp"

OPENTELEMETRY_BEGIN_NAMESPACE

// Define a fixture class for DataHub tests
class MetricsScopeTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        opentelemetry::sdk::common::internal_log::GlobalLogHandler::SetLogLevel(opentelemetry::sdk::common::internal_log::LogLevel::Error);
        m_spMetricsScope = std::make_shared<metricsManager::MetricsScope>();
        m_spMetricsScope->initialize(false, 1000, 300);
    }

    std::shared_ptr<metricsManager::MetricsScope> m_spMetricsScope;
};

TEST_F(MetricsScopeTest, MetricsNull)
{
    EXPECT_TRUE(m_spMetricsScope->getAllMetrics().isNull());
}

TEST_F(MetricsScopeTest, MetricsNotExist)
{
    EXPECT_TRUE(m_spMetricsScope->getAllMetrics("noExist").isNull());
}

TEST_F(MetricsScopeTest, MetricsCounter)
{
    auto counter = m_spMetricsScope->getCounterDouble("counter_0");
    counter->addValue(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    auto arrayCounter = m_spMetricsScope->getAllMetrics().getJson("/counter_0").value().getArray("/records").value();
    arrayCounter[0].erase("/start_time");

    auto expected = json::Json {R"({
        "instrument_name":"counter_0",
        "instrument_description":"",
        "unit":"",
        "type":"Counter",
        "attributes":[
            {"type":"SumPointData",
            "value":1.0}
            ]})"};

    EXPECT_EQ(expected, arrayCounter[0]);
}

TEST_F(MetricsScopeTest, MetricsUpDownCounter)
{
    auto counterUpDown = m_spMetricsScope->getUpDownCounterDouble("counterUpDown_0");
    counterUpDown->addValue(-1);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    auto arrayCounter = m_spMetricsScope->getAllMetrics().getJson("/counterUpDown_0").value().getArray("/records").value();
    arrayCounter[0].erase("/start_time");

    auto expected = json::Json {R"({
        "instrument_name":"counterUpDown_0",
        "instrument_description":"",
        "unit":"",
        "type":"UpDownCounter",
        "attributes":[
            {"type":"SumPointData",
            "value":-1.0}
            ]})"};

    EXPECT_EQ(expected, arrayCounter[0]);
}

TEST_F(MetricsScopeTest, MetricsHistogram)
{
    auto histogram = m_spMetricsScope->getHistogramDouble("histogram_0");
    histogram->recordValue(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    auto arrayHistogram = m_spMetricsScope->getAllMetrics().getJson("/histogram_0").value().getArray("/records").value();
    arrayHistogram[0].erase("/start_time");

    auto expected = json::Json {R"({
        "instrument_name":"histogram_0",
        "instrument_description":"",
        "unit":"",
        "type":"Histogram",
        "attributes":[
            {"type":"HistogramPointData",
            "count":1,
            "sum":1.0,
            "min":1.0,
            "max":1.0,
            "buckets":[0.0,5.0,10.0,25.0,50.0,75.0,100.0,250.0,500.0,750.0,1000.0,2500.0,5000.0,7500.0,10000.0],
            "counts":[0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            }]})"};

    EXPECT_EQ(expected, arrayHistogram[0]);
}

TEST_F(MetricsScopeTest, MetricsGauge)
{
    auto gauge = m_spMetricsScope->getGaugeDouble("gauge_0", 1);
    gauge->setValue(1);
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    auto arrayGauge = m_spMetricsScope->getAllMetrics().getJson("/gauge_0").value().getArray("/records").value();
    auto subArrayGauge = arrayGauge[0].getArray("/attributes").value();
    subArrayGauge[0].erase("/timestamp");

    auto expected = json::Json {R"({
        "type":"LastValuePointData",
        "valid":true,
        "value":1.0
        })"};

    EXPECT_EQ(expected, subArrayGauge[0]);
}

OPENTELEMETRY_END_NAMESPACE
