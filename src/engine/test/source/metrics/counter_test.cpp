#include "opentelemetry/sdk/version/version.h"
#include "exporterHandler.hpp"
#include "readerHandler.hpp"
#include "providerHandler.hpp"
#include "gtest/gtest.h"

namespace counter_test
{

void f1()
{
    std::cout << "f1\n";
}

void f2()
{
    std::cout << "f2\n";
}

void f3()
{
    f1();
    f2();
}

class MetricsInstrumentationTest : public ::testing::Test
{
protected:
    std::shared_ptr<MetricsContext> m_spContext;
    MetricsInstrumentationTest() = default;
    ~MetricsInstrumentationTest() override = default;
    void SetUp() override { m_spContext = std::make_shared<MetricsContext>(); }
    void TearDown() override
    {
        std::shared_ptr<opentelemetry::trace::TracerProvider> none;
        opentelemetry::trace::Provider::SetTracerProvider(none);
    }
};

TEST_F(MetricsInstrumentationTest, CounterTest)
{
    std::string name {"ostream_metric_example"};
    std::string version {"1.2.0"};
    std::string schema {"https://opentelemetry.io/schemas/1.2.0"};

    /*
    Initialize an exporter and a reader.
    In this case, we initialize an OStream Exporter which will print to stdout by
    default. The reader periodically collects metrics from the Aggregation Store and
    exports them.
    */

    m_spContext->providerType = ProviderTypes::Meter;
    m_spContext->exporterType = ExportersTypes::Metrics;
    m_spContext->processorType = ProcessorsTypes::Simple;
    auto exporter = std::make_shared<ExporterHandler>();
    auto reader = std::make_shared<ReaderHandler>();
    m_spContext->export_interval_millis = std::chrono::milliseconds(1000);
    m_spContext->export_timeout_millis = std::chrono::milliseconds(500);
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(reader)->setNext(provider);
    exporter->handleRequest(m_spContext);
}
} // namespace counter_test