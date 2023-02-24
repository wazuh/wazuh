#include "opentelemetry/sdk/version/version.h"
#include "exporterHandler.hpp"
#include "readerHandler.hpp"
#include "providerHandler.hpp"
#include "opentelemetry/metrics/provider.h"
#include "gtest/gtest.h"

void counterExample(const std::string &name)
{
    std::string counter_name = name + "_counter";
    auto provider = opentelemetry::metrics::Provider::GetMeterProvider();
    opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name, "1.2.0");
    auto double_counter = meter->CreateDoubleCounter(counter_name);

    for (uint32_t i = 0; i < 20; ++i)
    {
        double val = (rand() % 700) + 1.1;
        double_counter->Add(val);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
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
    /*
    Initialize an exporter and a reader.
    In this case, we initialize an OStream Exporter which will print to stdout by
    default. The reader periodically collects metrics from the Aggregation Store and
    exports them.
    */
    m_spContext->loggingFileExport = true;
    m_spContext->outputFile = "counter.txt";
    m_spContext->providerType = ProviderTypes::Meter;
    m_spContext->instrumentType = InstrumentTypes::Counter;
    m_spContext->export_interval_millis = std::chrono::milliseconds(1000);
    m_spContext->export_timeout_millis = std::chrono::milliseconds(500);
    m_spContext->counterName = "example";
    auto exporter = std::make_shared<ExporterHandler>();
    auto reader = std::make_shared<ReaderHandler>();
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(reader)->setNext(provider);
    exporter->handleRequest(m_spContext);
    counterExample(m_spContext->counterName);
}
