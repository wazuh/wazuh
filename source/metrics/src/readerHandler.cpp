#include "readerHandler.hpp"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"


std::shared_ptr<MetricsContext> ReaderHandler::handleRequest(std::shared_ptr<MetricsContext> data)
{
    create(data);
    return AbstractHandler<std::shared_ptr<MetricsContext>>::handleRequest(data);
}

void ReaderHandler::create(std::shared_ptr<MetricsContext> data)
{
    if (data->metricExporter != nullptr)
    {
        opentelemetry::sdk::metrics::PeriodicExportingMetricReaderOptions options;
        options.export_interval_millis = data->export_interval_millis;
        options.export_timeout_millis = data->export_timeout_millis;

        std::unique_ptr<opentelemetry::sdk::metrics::MetricReader> reader {
        new opentelemetry::sdk::metrics::PeriodicExportingMetricReader(std::move(data->metricExporter), options)};
        data->reader = std::move(reader);
    }
}
