#include "processorHandler.hpp"
#include "opentelemetry/sdk/trace/simple_processor_factory.h"

std::shared_ptr<MetricsContext> ProcessorHandler::handleRequest(std::shared_ptr<MetricsContext> data)
{
    create(data);
    return AbstractHandler<std::shared_ptr<MetricsContext>>::handleRequest(data);
}

void ProcessorHandler::create(std::shared_ptr<MetricsContext> data)
{
    switch (data->processorType)
    {
        case ProcessorsTypes::Simple:
            {
                if (data->exporter != nullptr)
                {
                    data->processor = opentelemetry::sdk::trace::SimpleSpanProcessorFactory::Create(std::move(data->exporter));
                    break;
                }
            }
        /*case ProcessorsTypes::Batch:
            {
                auto inMemorySpanData = std::make_shared<opentelemetry::exporter::memory::InMemorySpanData>(data->bufferSizeMemoryExporter);
                data->exporter = opentelemetry::exporter::memory::InMemorySpanExporterFactory::Create(inMemorySpanData, data->bufferSizeMemoryExporter);
                break;
            }
        case ProcessorsTypes::MultiProcessor:
            {
                opentelemetry::exporter::zipkin::ZipkinExporterOptions opts;
                data->exporter = opentelemetry::exporter::zipkin::ZipkinExporterFactory::Create(opts);
                break;
            }
        */
        default:
            data->processor = nullptr;
            break;
    }
}