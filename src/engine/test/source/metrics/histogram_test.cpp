#include "exporterHandler.hpp"
#include "readerHandler.hpp"
#include "providerHandler.hpp"
#include "opentelemetry/metrics/provider.h"
#include <gtest/gtest.h>

std::map<std::string, std::string> get_random_attr()
{
  const std::vector<std::pair<std::string, std::string>> labels = {{"key1", "value1"},
                                                                   {"key2", "value2"},
                                                                   {"key3", "value3"},
                                                                   {"key4", "value4"},
                                                                   {"key5", "value5"}};
  return std::map<std::string, std::string>{labels[rand() % (labels.size() - 1)],
                                            labels[rand() % (labels.size() - 1)]};
}

void histogramExample(const std::string &name)
{
  std::string histogram_name                  = name + "_histogram";
  auto provider                               = opentelemetry::metrics::Provider::GetMeterProvider();
  opentelemetry::nostd::shared_ptr<opentelemetry::metrics::Meter> meter = provider->GetMeter(name, "1.2.0");
  auto histogram_counter = meter->CreateDoubleHistogram(histogram_name, "des", "unit");
  auto context           = opentelemetry::context::Context{};
  for (uint32_t i = 0; i < 2; ++i)
  {
    double val                                = (rand() % 700) + 1.1;
    std::map<std::string, std::string> labels = get_random_attr();
    auto labelkv = opentelemetry::common::KeyValueIterableView<decltype(labels)>{labels};
    histogram_counter->Record(val, labelkv, context);
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
  }
}

class HistogramTest : public ::testing::Test
{
protected:
    std::shared_ptr<MetricsContext> m_spContext;
    HistogramTest() = default;
    ~HistogramTest() override = default;
    void SetUp() override
    {
        m_spContext = std::make_shared<MetricsContext>();
    }
    void TearDown() override
    {
        std::shared_ptr<opentelemetry::metrics::MeterProvider> none;
        opentelemetry::metrics::Provider::SetMeterProvider(none);
        if (m_spContext->file.is_open())
        {
          m_spContext->file.close();
        }
    }
};

TEST_F(HistogramTest, example)
{
  m_spContext->loggingFileExport = true;
  m_spContext->outputFile = "histrogram.txt";
  m_spContext->providerType = ProviderTypes::Meter;
  m_spContext->instrumentType = InstrumentTypes::Histogram;
  m_spContext->histogramVector = {0.0,    50.0,   100.0,  250.0,   500.0,  750.0,
                                          1000.0, 2500.0, 5000.0, 10000.0, 20000.0};
  m_spContext->export_interval_millis = std::chrono::milliseconds(1000);
  m_spContext->export_timeout_millis = std::chrono::milliseconds(500);
  m_spContext->histogramName = "example";
  auto exporter = std::make_shared<ExporterHandler>();
  auto reader = std::make_shared<ReaderHandler>();
  auto provider = std::make_shared<ProviderHandler>();
  exporter->setNext(reader)->setNext(provider);
  exporter->handleRequest(m_spContext);
  histogramExample(m_spContext->histogramName);
}
