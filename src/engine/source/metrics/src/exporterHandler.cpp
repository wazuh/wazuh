#include "exporterHandler.hpp"
#include "opentelemetry/exporters/zipkin/zipkin_exporter_factory.h"
#include "opentelemetry/exporters/ostream/span_exporter_factory.h"
#include "opentelemetry/exporters/memory/in_memory_span_exporter_factory.h"
#include "opentelemetry/exporters/ostream/metric_exporter.h"
#include <fstream>

std::shared_ptr<MetricsContext> ExporterHandler::handleRequest(std::shared_ptr<MetricsContext> data)
{
    create(data);
    return AbstractHandler<std::shared_ptr<MetricsContext>>::handleRequest(data);
}

void ExporterHandler::create(std::shared_ptr<MetricsContext> data)
{
    switch (data->exporterType)
    {
        case ExportersTypes::Logging:
            {
                if (data->loggingFileExport)
                {
                    data->file.open(data->outputFile);
                    data->exporter = opentelemetry::exporter::trace::OStreamSpanExporterFactory::Create(data->file);
                }
                else
                {
                    data->exporter = opentelemetry::exporter::trace::OStreamSpanExporterFactory::Create();
                }
                break;
            }
        case ExportersTypes::Memory:
            {
                data->inMemorySpanData = std::make_shared<opentelemetry::exporter::memory::InMemorySpanData>(data->bufferSizeMemoryExporter);
                data->exporter = opentelemetry::exporter::memory::InMemorySpanExporterFactory::Create(data->inMemorySpanData, data->bufferSizeMemoryExporter);
                break;
            }
        case ExportersTypes::Zipkin:
            {
                opentelemetry::exporter::zipkin::ZipkinExporterOptions opts;
                data->exporter = opentelemetry::exporter::zipkin::ZipkinExporterFactory::Create(opts);
                break;
            }
        case ExportersTypes::Metrics:
            {
                if (data->loggingFileExport)
                {
                    data->file.open(data->outputFile);
                    std::unique_ptr<opentelemetry::sdk::metrics::PushMetricExporter> exporter {
                        new opentelemetry::exporter::metrics::OStreamMetricExporter(data->file)};
                    data->metricExporter = std::move(exporter);
                }
                else
                {
                    std::unique_ptr<opentelemetry::sdk::metrics::PushMetricExporter> exporter {
                        new opentelemetry::exporter::metrics::OStreamMetricExporter()};
                    data->metricExporter = std::move(exporter);
                }
                break;
            }
        default:
            data->exporter = nullptr;
            break;
    }
}
