#ifndef _METRICS_CONTEXT_H
#define _METRICS_CONTEXT_H

#include "opentelemetry/sdk/trace/processor.h"
#include "opentelemetry/sdk/trace/exporter.h"
#include "opentelemetry/trace/provider.h"
#include <fstream>

enum class ExportersTypes
{
    Logging,
    Memory,
    Zipkin,
    JaegerUDP,
    JaegerHTTP,
    OtlpRPC,
    OtlpHTTP
};

enum class ProcessorsTypes
{
    Simple,
    Batch,
    MultiProcessor
};

struct MetricsContext
{
    bool loggingFileExport;
    std::string outputFile;
    size_t bufferSizeMemoryExporter;
    ExportersTypes exporterType;
    ProcessorsTypes processorType;
    std::unique_ptr<opentelemetry::sdk::trace::SpanExporter> exporter;
    std::unique_ptr<opentelemetry::sdk::trace::SpanProcessor> processor;
    std::shared_ptr<opentelemetry::trace::TracerProvider> provider;
    std::ofstream file;
};

#endif // _METRICS_CONTEXT_H
