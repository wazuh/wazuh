#include "providerHandler.hpp"
#include "opentelemetry/sdk/trace/tracer_provider_factory.h"
#include "opentelemetry/metrics/provider.h"
#include "opentelemetry/sdk/metrics/aggregation/default_aggregation.h"
#include "opentelemetry/sdk/metrics/aggregation/histogram_aggregation.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"
#include "opentelemetry/sdk/metrics/meter.h"
#include "opentelemetry/sdk/metrics/meter_provider.h"

std::shared_ptr<MetricsContext> ProviderHandler::handleRequest(std::shared_ptr<MetricsContext> data)
{
    create(data);
    return AbstractHandler<std::shared_ptr<MetricsContext>>::handleRequest(data);
}

void ProviderHandler::create(std::shared_ptr<MetricsContext> data)
{
    switch (data->providerType)
    {
        case ProviderTypes::Tracer:
        {
            if (data->processor != nullptr)
            {
                opentelemetry::sdk::resource::ResourceAttributes attributes = {{"service.name", "zipkin_demo_service"}};
                auto resource = opentelemetry::sdk::resource::Resource::Create(attributes);
                data->traceProvider = opentelemetry::sdk::trace::TracerProviderFactory::Create(std::move(data->processor), resource);
                opentelemetry::trace::Provider::SetTracerProvider(data->traceProvider);
            }
            break;
        }
        case ProviderTypes::Meter:
        {
            auto provider = std::shared_ptr<opentelemetry::metrics::MeterProvider>(new opentelemetry::sdk::metrics::MeterProvider());
            data->meterProvider = std::static_pointer_cast<opentelemetry::sdk::metrics::MeterProvider>(provider);
            data->meterProvider->AddMetricReader(std::move(data->reader));
            opentelemetry::metrics::Provider::SetMeterProvider(provider);
            break;
        }
    }
}
