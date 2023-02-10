#include "exporterHandler.hpp"
#include "processorHandler.hpp"
#include "providerHandler.hpp"
#include "gtest/gtest.h"
#include "opentelemetry/sdk/version/version.h"

opentelemetry::nostd::shared_ptr<opentelemetry::trace::Tracer> get_tracer()
{
  auto provider = opentelemetry::trace::Provider::GetTracerProvider();
  return provider->GetTracer("foo_library", OPENTELEMETRY_SDK_VERSION);
}

void f1()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("f1"));
}

void f2()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("f2"));

  f1();
  f1();
}

void f3()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("f3"));
}

void foo_library()
{
  auto scoped_span = opentelemetry::trace::Scope(get_tracer()->StartSpan("library"));

  f2();
  f3();
}

class IntegrationTest : public ::testing::Test
{
protected:
    std::shared_ptr<MetricsContext> m_spContext;
    IntegrationTest() = default;
    ~IntegrationTest() override = default;
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

// To test this you have to download the docker image of zipkin into the VM using docker run -d -p 9411:9411 openzipkin/zipkin
// and then reassign the ports to access the browser http://localhost:new_port.
TEST_F(IntegrationTest, exporterZipkin)
{
    m_spContext->exporterType = ExportersTypes::Zipkin;
    m_spContext->processorType = ProcessorsTypes::Simple;
    auto exporter = std::make_shared<ExporterHandler>();
    auto processor = std::make_shared<ProcessorHandler>();
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(processor)->setNext(provider);
    exporter->handleRequest(m_spContext);
    foo_library();
}

TEST_F(IntegrationTest, exporterLoggingCout)
{
    m_spContext->exporterType = ExportersTypes::Logging;
    m_spContext->processorType = ProcessorsTypes::Simple;
    auto exporter = std::make_shared<ExporterHandler>();
    auto processor = std::make_shared<ProcessorHandler>();
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(processor)->setNext(provider);
    exporter->handleRequest(m_spContext);
    foo_library();
}

TEST_F(IntegrationTest, exporterLoggingFile)
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
    foo_library();
}

TEST_F(IntegrationTest, exporterMemory)
{
    m_spContext->exporterType = ExportersTypes::Memory;
    m_spContext->processorType = ProcessorsTypes::Simple;
    m_spContext->bufferSizeMemoryExporter = 100;
    auto exporter = std::make_shared<ExporterHandler>();
    auto processor = std::make_shared<ProcessorHandler>();
    auto provider = std::make_shared<ProviderHandler>();
    exporter->setNext(processor)->setNext(provider);
    exporter->handleRequest(m_spContext);
    foo_library();

    // TODO: this data is encoded, add some way to decode (for example UTF-8)
    for (const auto& spans : m_spContext->inMemorySpanData->GetSpans())
    {
      std::cout << "GetTraceId: << " << std::string((char*)spans->GetTraceId().Id().data()) << std::endl;
      std::cout << "GetSpanId: << " << std::string((char*)spans->GetSpanId().Id().data()) << std::endl;
    }
}
