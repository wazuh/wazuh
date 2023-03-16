#include <metrics/metricsManager.hpp>
#include <gtest/gtest.h>

const auto INPUT_PATH {(std::filesystem::current_path() / "source/metrics/input_files/metrics-config.json").string()};
/*
class Measurement
{
public:
  static void Fetcher(opentelemetry::metrics::ObserverResult observer_result, void *)
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
*/

class MetricsOtlMeterTest : public ::testing::Test
{
protected:
    MetricsOtlMeterTest() = default;
    ~MetricsOtlMeterTest() override = default;
    void TearDown() override
    {
//        Metrics::instance().clean();
    }
};

TEST_F(MetricsOtlMeterTest, invalidValueCounter)
{
  //  Metrics::instance().initMetrics("example", INPUT_PATH);
    //EXPECT_ANY_THROW(Metrics::instance().addCounterValue("Sockets", -1UL));
}

TEST_F(MetricsOtlMeterTest, repeatedInit)
{
    //EXPECT_ANY_THROW(Metrics::instance().initMetrics("example", INPUT_PATH));
}

TEST_F(MetricsOtlMeterTest, nameCounterNotDefined)
{
    //EXPECT_ANY_THROW(Metrics::instance().addCounterValue("RandomName", 1UL));
}

TEST_F(MetricsOtlMeterTest, sucessMeter)
{
/*    Metrics::instance().setScopeSpan("TracerExampleOne");
    for (auto i = 0; i < 10; i ++)
    {
        Metrics::instance().addCounterValue("Test.CountExample", 1UL);
        Metrics::instance().addHistogramValue("Test.HistogramExample", 32.7);
        Metrics::instance().addUpDownCounterValue("Test.UpDownCountExample", 1L);
        std::this_thread::sleep_for(std::chrono::milliseconds(90));
        if (i == 6)
        {
            Metrics::instance().addUpDownCounterValue("Test.UpDownCountExample", -2L); // here the counter is at 7 and when restoring 2 there should be a 5.
        }
    }
    Metrics::instance().setScopeSpan("TracerExampleTwo");
    */
}

TEST_F(MetricsOtlMeterTest, sucessMeterGauge)
{
    /*
    Metrics::instance().addObservableGauge("ObservableGaugeExample", Measurement::Fetcher);
    for (uint32_t i = 0; i < 5; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    Metrics::instance().removeObservableGauge("ObservableGaugeExample", Measurement::Fetcher);
    */

}
