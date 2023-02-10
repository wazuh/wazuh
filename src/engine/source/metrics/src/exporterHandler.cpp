#include "exporterHandler.hpp"
#include "opentelemetry/exporters/zipkin/zipkin_exporter_factory.h"
#include "opentelemetry/exporters/ostream/span_exporter_factory.h"
#include "opentelemetry/exporters/memory/in_memory_span_exporter_factory.h"
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
                    break;
                }
                else
                {
                    data->exporter = opentelemetry::exporter::trace::OStreamSpanExporterFactory::Create();
                    break;
                }
            }
        case ExportersTypes::Memory:
            {
                auto inMemorySpanData = std::make_shared<opentelemetry::exporter::memory::InMemorySpanData>(data->bufferSizeMemoryExporter);
                data->exporter = opentelemetry::exporter::memory::InMemorySpanExporterFactory::Create(inMemorySpanData, data->bufferSizeMemoryExporter);
                break;
            }
        case ExportersTypes::Zipkin:
            {
                opentelemetry::exporter::zipkin::ZipkinExporterOptions opts;
                data->exporter = opentelemetry::exporter::zipkin::ZipkinExporterFactory::Create(opts);
                break;
            }
        default:
            data->exporter = nullptr;
            break;
    }
}
