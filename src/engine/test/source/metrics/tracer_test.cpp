#include "exporterHandler.hpp"
#include "processorHandler.hpp"
#include "providerHandler.hpp"
#include "gtest/gtest.h"
#include "opentelemetry/sdk/version/version.h"

namespace test_tracer
{
opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> get_tracer()
{
  auto provider = opentelemetry::trace::Provider::GetTracerProvider();
  return provider->GetTracer("foo_library", OPENTELEMETRY_SDK_VERSION);
}

void f1()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("f1"));
  std::cout <<"f1\n";
}

void f2()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("f2"));
  std::cout <<"f2\n";
}

void f3()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("f3"));
  f1();
  f2();
}

class TracerInstrumentationTest : public ::testing::Test
{
protected:
  std::shared_ptr<MetricsContext> m_spContext;
  TracerInstrumentationTest() = default;
  ~TracerInstrumentationTest() override = default;
  void SetUp() override
  {
      m_spContext = std::make_shared<MetricsContext>();
  }
  void TearDown() override
  {
    std::shared_ptr<opentelemetry::trace::TracerProvider> none;
    opentelemetry::trace::Provider::SetTracerProvider(none);
  }
};

TEST(TracerTest, GetCurrentSpan)
{
  std::unique_ptr<trace_api::Tracer> tracer(new trace_api::NoopTracer());
  opentelemetry::nostd::shared_ptr<trace_api::Span> span_first(new trace_api::NoopSpan(nullptr));
  opentelemetry::nostd::shared_ptr<trace_api::Span> span_second(new trace_api::NoopSpan(nullptr));

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

TEST_F(TracerInstrumentationTest, SetTracerOutputFile)
{
    m_spContext->exporterType = ExportersTypes::Logging;
    m_spContext->processorType = ProcessorsTypes::Simple;
    m_spContext->loggingFileExport = true;
    m_spContext->outputFile = "output.json";
    auto exporter = std::make_shared<ExporterHandler>();
    auto processor = std::make_shared<ProcessorHandler>();
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(processor)->setNext(provider);
    exporter->handleRequest(m_spContext);
    f3();
}

TEST_F(TracerInstrumentationTest, SetTracerOutputStd)
{
    m_spContext->exporterType = ExportersTypes::Memory;
    m_spContext->processorType = ProcessorsTypes::Simple;
    auto exporter = std::make_shared<ExporterHandler>();
    auto processor = std::make_shared<ProcessorHandler>();
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(processor)->setNext(provider);
    exporter->handleRequest(m_spContext);
    f3();
}
}