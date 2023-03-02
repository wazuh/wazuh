#include "opentelemetry/exporters/ostream/metric_exporter.h"
#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/aggregation/default_aggregation.h"
#include "opentelemetry/sdk/metrics/aggregation/histogram_aggregation.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"
#include "opentelemetry/sdk/metrics/meter.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"

#include <fstream>
#include <gtest/gtest.h>
#include <iostream>

namespace metric_sdk = opentelemetry::sdk::metrics;
namespace common = opentelemetry::common;
namespace exportermetrics = opentelemetry::exporter::metrics;
namespace metrics_api = opentelemetry::metrics;
namespace nostd = opentelemetry::nostd;

TEST(CounterTest, SetGlobalTraceProvider)
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

    std::ofstream file;
    file.open("counters.txt");

    std::unique_ptr<metric_sdk::PushMetricExporter> exporter {
        new exportermetrics::OStreamMetricExporter(file)};

    // Initialize and set the global MeterProvider
    metric_sdk::PeriodicExportingMetricReaderOptions options;
    options.export_interval_millis = std::chrono::milliseconds(1000);
    options.export_timeout_millis = std::chrono::milliseconds(500);

    std::unique_ptr<metric_sdk::MetricReader> reader {
        new metric_sdk::PeriodicExportingMetricReader(std::move(exporter), options)};

    /*
    Initialize a MeterProvider and add the reader. We will use this to obtain Meter
    objects in the future.
    */
    auto provider =
        std::shared_ptr<metrics_api::MeterProvider>(new metric_sdk::MeterProvider());
    auto p = std::static_pointer_cast<metric_sdk::MeterProvider>(provider);
    p->AddMetricReader(std::move(reader));

    /*
    Optional: Create a view to map the Counter Instrument to Sum Aggregation. Add this
    view to provider. View creation is optional unless we want to add custom aggregation
    config, and attribute processor. Metrics SDK will implicitly create a missing view
    with default mapping between Instrument and Aggregation*/
    // counter view
    std::string counter_name = name + "_counter";
    std::unique_ptr<metric_sdk::InstrumentSelector> instrument_selector {
        new metric_sdk::InstrumentSelector(metric_sdk::InstrumentType::kCounter,
                                           counter_name)};
    std::unique_ptr<metric_sdk::MeterSelector> meter_selector {
        new metric_sdk::MeterSelector(name, version, schema)};
    std::unique_ptr<metric_sdk::View> sum_view {new metric_sdk::View {
        name, "description", metric_sdk::AggregationType::kDefault}};
    p->AddView(
        std::move(instrument_selector), std::move(meter_selector), std::move(sum_view));

    metrics_api::Provider::SetMeterProvider(provider);

    {
        std::string counter_name = name + "_counter";
        auto provider = metrics_api::Provider::GetMeterProvider();
        nostd::shared_ptr<metrics_api::Meter> meter = provider->GetMeter(name, "1.2.0");
        auto double_counter = meter->CreateDoubleCounter(counter_name);

        for (uint32_t i = 0; i < 20; ++i)
        {
            double val = (rand() % 700) + 1.1;
            double_counter->Add(val);
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    std::shared_ptr<metrics_api::MeterProvider> none;
    metrics_api::Provider::SetMeterProvider(none);
    file.close();
}