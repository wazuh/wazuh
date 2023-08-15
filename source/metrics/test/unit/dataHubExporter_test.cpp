#include <gtest/gtest.h>

#include <metrics/dataHubExporter.hpp>

#include "mocks/mockDataHubExporter.hpp"

OPENTELEMETRY_BEGIN_NAMESPACE

// Define a fixture class for DataHub tests
class DataHubExporterTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_spMockDataHubExporter = std::make_shared<MockDataHubExporter>();
        m_spDataHubExporter = std::make_shared<exporter::metrics::DataHubExporter>(m_spMockDataHubExporter);
    }

    std::shared_ptr<MockDataHubExporter> m_spMockDataHubExporter;
    std::shared_ptr<exporter::metrics::DataHubExporter> m_spDataHubExporter;
};

TEST_F(DataHubExporterTest, SuccessExport)
{
    sdk::metrics::SumPointData sum_point_data{};
    sum_point_data.value_ = 10.0;
    sdk::metrics::SumPointData sum_point_data2{};
    sum_point_data2.value_ = 20.0;
    sdk::metrics::ResourceMetrics data;
    auto resource = opentelemetry::sdk::resource::Resource::Create(
    opentelemetry::sdk::resource::ResourceAttributes{});
    data.resource_ = &resource;
    auto scope     = opentelemetry::sdk::instrumentationscope::InstrumentationScope::Create(
    "library_name", "1.2.0");
    sdk::metrics::MetricData metric_data{
    sdk::metrics::InstrumentDescriptor{"library_name", "description", "unit",
                                    sdk::metrics::InstrumentType::kCounter,
                                    sdk::metrics::InstrumentValueType::kDouble},
    sdk::metrics::AggregationTemporality::kDelta, opentelemetry::common::SystemTimestamp{},
    opentelemetry::common::SystemTimestamp{},
    std::vector<sdk::metrics::PointDataAttributes>{
        {sdk::metrics::PointAttributes{{"a1", "b1"}}, sum_point_data},
        {sdk::metrics::PointAttributes{{"a1", "b1"}}, sum_point_data2}}};
    data.scope_metric_data_ = std::vector<sdk::metrics::ScopeMetrics>{
    {scope.get(), std::vector<sdk::metrics::MetricData>{metric_data}}};

    EXPECT_CALL(*m_spMockDataHubExporter, setResource(testing::_, testing::_));

    ASSERT_EQ(m_spDataHubExporter->Export(data), sdk::common::ExportResult::kSuccess);
}

TEST_F(DataHubExporterTest, SuccessExportWithoutSetResource)
{
    sdk::metrics::ResourceMetrics data;

    ASSERT_EQ(m_spDataHubExporter->Export(data), sdk::common::ExportResult::kSuccess);
}

TEST_F(DataHubExporterTest, FailedExport)
{
    sdk::metrics::ResourceMetrics data;

    m_spDataHubExporter->Shutdown(std::chrono::microseconds(10));

    ASSERT_EQ(m_spDataHubExporter->Export(data), sdk::common::ExportResult::kFailure);
}

OPENTELEMETRY_END_NAMESPACE
