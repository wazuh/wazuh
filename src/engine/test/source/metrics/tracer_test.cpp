// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "opentelemetry/exporters/ostream/span_exporter_factory.h"
#include "opentelemetry/sdk/trace/simple_processor_factory.h"
#include "opentelemetry/sdk/trace/tracer_provider_factory.h"
#include "opentelemetry/sdk/version/version.h"
#include "opentelemetry/trace/provider.h"

#include "opentelemetry/nostd/shared_ptr.h"
#include "opentelemetry/trace/noop.h"
#include "opentelemetry/trace/scope.h"

#include <gtest/gtest.h>
#include <fstream>

namespace trace_api = opentelemetry::trace;
namespace trace_sdk = opentelemetry::sdk::trace;
namespace trace_exporter = opentelemetry::exporter::trace;
namespace nostd = opentelemetry::nostd;
namespace context = opentelemetry::context;

class TracerInstrumentationTest : public ::testing::Test
{
public:
    static void f1()
    {
      auto scoped_span = trace_api::Scope(TracerInstrumentationTest::get_tracer()->StartSpan("f1"));
      std::cout <<"f1\n";
    };

    static void f2()
    {
      auto scoped_span = trace_api::Scope(TracerInstrumentationTest::get_tracer()->StartSpan("f2"));
      std::cout <<"f2\n";
    };

    static void f3()
    {
      auto scoped_span = trace_api::Scope(TracerInstrumentationTest::get_tracer()->StartSpan("f3"));
      f1();
      f2();
    };

    static nostd::shared_ptr<trace_api::Tracer> get_tracer()
    {
      auto provider = trace_api::Provider::GetTracerProvider();
      return provider->GetTracer("test_library", OPENTELEMETRY_SDK_VERSION);
    };
};

TEST(TracerTest, GetCurrentSpan)
{
  std::unique_ptr<trace_api::Tracer> tracer(new trace_api::NoopTracer());
  nostd::shared_ptr<trace_api::Span> span_first(new trace_api::NoopSpan(nullptr));
  nostd::shared_ptr<trace_api::Span> span_second(new trace_api::NoopSpan(nullptr));

  auto current = tracer->GetCurrentSpan();
  ASSERT_FALSE(current->GetContext().IsValid());

  {
    auto scope_first = tracer->WithActiveSpan(span_first);
    current          = tracer->GetCurrentSpan();
    ASSERT_EQ(current, span_first);

    {
      auto scope_second = tracer->WithActiveSpan(span_second);
      current           = tracer->GetCurrentSpan();
      ASSERT_EQ(current, span_second);
    }
    current = tracer->GetCurrentSpan();
    ASSERT_EQ(current, span_first);
  }

  current = tracer->GetCurrentSpan();
  ASSERT_FALSE(current->GetContext().IsValid());
}

TEST(TracerInstrumentationTest, SetTracerProvider)
{
  // Init tracer

  // Output file
  std::ofstream file;
  file.open("output.txt");

  // Create exporter
  auto exporter = trace_exporter::OStreamSpanExporterFactory::Create(file);
  ASSERT_NE(exporter, nullptr);

  // Create processor
  auto processor = trace_sdk::SimpleSpanProcessorFactory::Create(std::move(exporter));
  ASSERT_NE(processor, nullptr);

  // Create provider
  std::shared_ptr<opentelemetry::trace::TracerProvider> provider = trace_sdk::TracerProviderFactory::Create(std::move(processor));
  ASSERT_NE(provider, nullptr);

  // Set the global trace provider
  trace_api::Provider::SetTracerProvider(provider);

  // Rutines
  TracerInstrumentationTest::f1();
  TracerInstrumentationTest::f2();
  TracerInstrumentationTest::f3();

  // End tracer
  std::shared_ptr<opentelemetry::trace::TracerProvider> none;
  trace_api::Provider::SetTracerProvider(none);
}