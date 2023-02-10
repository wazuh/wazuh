#include "processorHandler.hpp"
#include "opentelemetry/sdk/trace/simple_processor_factory.h"
#include "opentelemetry/sdk/trace/batch_span_processor_factory.h"

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
        case ProcessorsTypes::Batch:
            {
                // See this example to do the test in Integration_test
                if (data->exporter != nullptr)
                {
                    opentelemetry::sdk::trace::BatchSpanProcessorOptions options{};
                    // We make the queue size `numSpans`*2+5 because when the queue is half full, a preemptive notif
                    // is sent to start an export call, which we want to avoid in this simple example.
                    options.max_queue_size = data->numSpans * 2 + 5;
                    // Time interval (in ms) between two consecutive exports.
                    options.schedule_delay_millis = std::chrono::milliseconds(data->timeIntervalBetweenExports);
                    // We export `numSpans` after every `schedule_delay_millis` milliseconds.
                    options.max_export_batch_size = data->numSpans;
                    data->processor = opentelemetry::sdk::trace::BatchSpanProcessorFactory::Create(std::move(data->exporter), options);
                    break;
                }
            }
        /*
        case ProcessorsTypes::MultiProcessor:
            {
            }
        */
        default:
            data->processor = nullptr;
            break;
    }
}
