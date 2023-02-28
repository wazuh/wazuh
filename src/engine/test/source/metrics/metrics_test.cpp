#include "metrics.hpp"
#include <gtest/gtest.h>
#include <filesystem>

const auto INPUT_PATH {(std::filesystem::current_path() / "source/metrics/input_files/metrics-config.json").string()};

class Measurement
{
public:
  static void Fetcher(opentelemetry::metrics::ObserverResult observer_result, void * /* state */)
  {
    if (opentelemetry::nostd::holds_alternative<
            opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<double>>>(observer_result))
    {
      double random_incr = (rand() % 5) + 1.1;
      value_ += random_incr;
      opentelemetry::nostd::get<opentelemetry::nostd::shared_ptr<opentelemetry::metrics::ObserverResultT<double>>>(observer_result)->Observe(value_);
    }
  }
  static double value_;
};
double Measurement::value_ = 0;

class MetricsTest : public ::testing::Test
{
protected:
    std::shared_ptr<Metrics> m_spMetrics;
    MetricsTest() = default;
    ~MetricsTest() override = default;
    void SetUp() override
    {
        m_spMetrics = std::make_shared<Metrics>();
        m_spMetrics->initMetrics("test", INPUT_PATH);
    }
};

TEST_F(MetricsTest, invalidValueCounter)
{
    EXPECT_ANY_THROW(m_spMetrics->addCounterValue("Sockets", -1UL));
}

TEST_F(MetricsTest, nameCounterNotDefined)
{
    EXPECT_ANY_THROW(m_spMetrics->addCounterValue("RandomName", 1UL));
}

TEST_F(MetricsTest, sucessMeterAndTracer)
{
    m_spMetrics->setScopeSpam("TracerExampleOne");
    for (auto i = 0; i < 10; i ++)
    {
        m_spMetrics->addCounterValue("CountExample", 1UL);
        std::this_thread::sleep_for(std::chrono::milliseconds(900));
        m_spMetrics->addHistogramValue("HistogramExample", 32.7);
        m_spMetrics->addUpDownCounterValue("UpDownCountExample", 1L);
        if (i == 6)
        {
            m_spMetrics->addUpDownCounterValue("UpDownCountExample", -2L); // here the counter is at 7 and when restoring 2 there should be a 5.
        }
    }
    m_spMetrics->setScopeSpam("TracerExampleTwo");
}

/*TEST_F(MetricsTest, sucessMeterGauge)
{
    m_spMetrics->addObservableGauge("ObservableGaugeExample", Measurement::Fetcher);
    for (uint32_t i = 0; i < 20; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}
*/
