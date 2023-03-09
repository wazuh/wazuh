#ifndef _METRICS_CONTEXT_H
#define _METRICS_CONTEXT_H

#include "opentelemetry/sdk/trace/processor.h"
#include "opentelemetry/sdk/trace/exporter.h"
#include "opentelemetry/trace/provider.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/view/instrument_selector.h"
#include "opentelemetry/exporters/memory/in_memory_span_data.h"
#include "opentelemetry/exporters/ostream/metric_exporter.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"
#include "opentelemetry/sdk/metrics/instruments.h"
#include <fstream>

enum class ExportersTypes
{
    Logging,
    Memory,
    OtlpRPC,
    OtlpHTTP,
    Zipkin
};

enum class ProcessorsTypes
{
    Batch,
    MultiProcessor,
    Simple,
};

enum class ProviderTypes
{
    Meter,
    Tracer
};

enum class InstrumentTypes
{
    Counter,
    Histogram,
    UpDownCounter,
    ObservableCounter,
    ObservableGauge,
    ObservableUpDownCounter
};

enum class SubType
{
    Double,
    Int64,
    UInt64
};

struct MetricsContext
{
    // TODO: add doxygen documentation
    bool enable;
    bool dataHubEnable{false};
    std::string outputFile;
    std::string name;
    std::string unit;
    std::string description;
    size_t bufferSizeMemoryExporter;
    ExportersTypes exporterType;
    ProcessorsTypes processorType;
    ProviderTypes providerType;
    InstrumentTypes instrumentType;
    std::vector<double> histogramVector;
    SubType subType;
    std::unique_ptr<opentelemetry::sdk::trace::SpanExporter> exporter;
    std::unique_ptr<opentelemetry::sdk::metrics::PushMetricExporter> metricExporter;
    std::unique_ptr<opentelemetry::sdk::metrics::MetricReader> reader;
    std::unique_ptr<opentelemetry::sdk::trace::SpanProcessor> processor;
    std::shared_ptr<opentelemetry::trace::TracerProvider> traceProvider;
    std::shared_ptr<opentelemetry::sdk::metrics::MeterProvider> meterProvider;
    std::shared_ptr<opentelemetry::exporter::memory::InMemorySpanData> inMemorySpanData;
    std::ofstream file;
    int timeIntervalBetweenExports;
    int numSpans;

    std::chrono::milliseconds export_interval_millis;
    std::chrono::milliseconds export_timeout_millis;
};

#endif // _METRICS_CONTEXT_H
