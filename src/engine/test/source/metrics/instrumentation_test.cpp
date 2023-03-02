#include "opentelemetry/exporters/ostream/span_exporter_factory.h"
#include "opentelemetry/sdk/trace/simple_processor_factory.h"
#include "opentelemetry/sdk/trace/tracer_provider_factory.h"
#include "opentelemetry/trace/provider.h"

#include <gtest/gtest.h>

namespace trace_api      = opentelemetry::trace;
namespace trace_sdk      = opentelemetry::sdk::trace;
namespace trace_exporter = opentelemetry::exporter::trace;

TEST(InstrumentationTest, SetGlobalTraceProvider)
{
  auto exporter  = trace_exporter::OStreamSpanExporterFactory::Create();
  ASSERT_NE(exporter, nullptr);
  auto processor = trace_sdk::SimpleSpanProcessorFactory::Create(std::move(exporter));
  ASSERT_NE(processor, nullptr);
  std::shared_ptr<opentelemetry::trace::TracerProvider> provider = trace_sdk::TracerProviderFactory::Create(std::move(processor));
//  trace_api::Provider::SetTracerProvider(provider);
}
