#include "providerHandler.hpp"
#include "opentelemetry/sdk/trace/tracer_provider_factory.h"

std::shared_ptr<MetricsContext> ProviderHandler::handleRequest(std::shared_ptr<MetricsContext> data)
{
    create(data);
    return AbstractHandler<std::shared_ptr<MetricsContext>>::handleRequest(data);
}

void ProviderHandler::create(std::shared_ptr<MetricsContext> data)
{
    switch (data->providerTypes)
    {
        case ProviderTypes::Tracer:
        {
            if (data->processor != nullptr)
            {
                opentelemetry::sdk::resource::ResourceAttributes attributes = {{"service.name", "zipkin_demo_service"}};
                auto resource = opentelemetry::sdk::resource::Resource::Create(attributes);
                data->provider = opentelemetry::sdk::trace::TracerProviderFactory::Create(std::move(data->processor), resource);
                opentelemetry::trace::Provider::SetTracerProvider(data->provider);
            }
            break;
        }
        case ProviderTypes::Meter:
        {
            // TODO
        }
        default:
            data->provider = nullptr;
            break;
        }
}
