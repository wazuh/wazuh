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

            switch (data->instrumentType)
            {
                case opentelemetry::sdk::metrics::InstrumentType::kHistogram:
                {
                    std::string version{"1.2.0"};
                    std::string schema{"https://opentelemetry.io/schemas/1.2.0"};
                    auto name = data->histogramName + "_histogram";
                    auto instrumentSelector = std::unique_ptr<opentelemetry::sdk::metrics::InstrumentSelector>(new opentelemetry::sdk::metrics::InstrumentSelector(data->instrumentType, name));
                    auto meterSelector = std::unique_ptr<opentelemetry::sdk::metrics::MeterSelector>(new opentelemetry::sdk::metrics::MeterSelector(data->histogramName, version, schema));
                    std::shared_ptr<opentelemetry::sdk::metrics::AggregationConfig> aggregation_config {new opentelemetry::sdk::metrics::HistogramAggregationConfig};
                    static_cast<opentelemetry::sdk::metrics::HistogramAggregationConfig *>(aggregation_config.get())->boundaries_ = data->histogramVector;
                    std::unique_ptr<opentelemetry::sdk::metrics::View> histogramView{new opentelemetry::sdk::metrics::View{
                    data->histogramName, "description", opentelemetry::sdk::metrics::AggregationType::kHistogram, aggregation_config}};
                    data->meterProvider->AddView(std::move(instrumentSelector), std::move(meterSelector), std::move(histogramView));
                    opentelemetry::metrics::Provider::SetMeterProvider(provider);
                    break;
                }
                case opentelemetry::sdk::metrics::InstrumentType::kCounter:
                {
                    std::string version{"1.2.0"};
                    std::string schema{"https://opentelemetry.io/schemas/1.2.0"};
                    auto name = data->counterName + "_counter";
                    auto instrumentSelector = std::unique_ptr<opentelemetry::sdk::metrics::InstrumentSelector>(new opentelemetry::sdk::metrics::InstrumentSelector(data->instrumentType, name));
                    auto meterSelector = std::unique_ptr<opentelemetry::sdk::metrics::MeterSelector>(new opentelemetry::sdk::metrics::MeterSelector(data->counterName, version, schema));
                    std::unique_ptr<opentelemetry::sdk::metrics::View> counterView{new opentelemetry::sdk::metrics::View{
                    data->counterName, "description", data->aggregationType }};
                    data->meterProvider->AddView(std::move(instrumentSelector), std::move(meterSelector), std::move(counterView));
                    opentelemetry::metrics::Provider::SetMeterProvider(provider);
                    break;
                }
                default:
                    break;
            }
        }
    }
}
