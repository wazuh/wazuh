#ifndef _I_METRICS_SCOPE_H
#define _I_METRICS_SCOPE_H

#include <metrics/iMetricsInstruments.hpp>

namespace metricsManager
{

class IMetricsScope
{
public:
  /**
   * @brief Gets a double counter.
   *
   * @param name The name of the counter.
   * @return A shared pointer to the counter.
   */
  virtual std::shared_ptr<iCounter<double>> getCounterDouble(const std::string& name) = 0;

  /**
   * @brief Gets an unsigned integer counter.
   *
   * @param name The name of the counter.
   * @return A shared pointer to the counter.
   */
  virtual std::shared_ptr<iCounter<uint64_t>> getCounterUInteger(const std::string& name) = 0;

  /**
   * @brief Gets a double up-down counter.
   *
   * @param name The name of the counter.
   * @return A shared pointer to the counter.
   */
  virtual std::shared_ptr<iCounter<double>> getUpDownCounterDouble(const std::string& name) = 0;

  /**
   * @brief Gets an integer up-down counter.
   *
   * @param name The name of the counter.
   * @return A shared pointer to the counter.
   */
  virtual std::shared_ptr<iCounter<int64_t>> getUpDownCounterInteger(const std::string& name) = 0;

  /**
   * @brief Gets a double histogram.
   *
   * @param name The name of the histogram.
   * @return A shared pointer to the histogram.
   */
  virtual std::shared_ptr<iHistogram<double>> getHistogramDouble(const std::string& name) = 0;

  /**
   * @brief Gets an unsigned integer histogram.
   *
   * @param name The name of the histogram.
   * @return A shared pointer to the histogram.
   */
  virtual std::shared_ptr<iHistogram<uint64_t>> getHistogramUInteger(const std::string& name) = 0;

  /**
   * @brief Gets an integer gauge.
   *
   * @param name The name of the gauge.
   * @param defaultValue The default value of the gauge.
   * @return A shared pointer to the gauge.
   */
  virtual std::shared_ptr<iGauge<int64_t>> getGaugeInteger(const std::string& name, int64_t defaultValue) = 0;

  /**
   * @brief Gets a double gauge.
   *
   * @param name The name of the gauge.
   * @param defaultValue The default value of the gauge.
   * @return A shared pointer to the gauge.
   */
  virtual std::shared_ptr<iGauge<double>> getGaugeDouble(const std::string& name, double defaultValue) = 0;
};

} // namespace metricsManager

#endif // _I_METRICS_SCOPE_H
