#ifndef _METRIC_METRIC_DOUBLEHISTOGRAM_HPP
#define _METRIC_METRIC_DOUBLEHISTOGRAM_HPP

#include <metrics/imetric.hpp>

#include "metric/metric.hpp"
#include "ot.hpp"

namespace metrics
{
using OtDoubleHistogramPtr = otapi::unique_ptr<otapi::Histogram<double>>;

class DoubleHistogram : public BaseOtMetric<double>
{
private:
    OtDoubleHistogramPtr m_histogram;

public:
    DoubleHistogram(std::string&& name, std::string&& description, std::string&& unit)
        : BaseOtMetric<double>(std::move(name), std::move(description), std::move(unit))
        , m_histogram(nullptr)
    {
    }

    DoubleHistogram(const DoubleHistogram&) = delete;
    DoubleHistogram& operator=(const DoubleHistogram&) = delete;
    DoubleHistogram(DoubleHistogram&&) = delete;
    DoubleHistogram& operator=(DoubleHistogram&&) = delete;

    ~DoubleHistogram() override = default;

    void otCreate() override
    {
        m_histogram = otapi::Provider::GetMeterProvider()
                          ->GetMeter(DEFAULT_METER_NAME)
                          ->CreateDoubleHistogram(m_name, m_description, m_unit);
    }

    void otDestroy() override { m_histogram.reset(); }

    void otUpdate(double value) override
    {
        if (m_histogram)
        {
            m_histogram->Record(value, otapi::RuntimeContext::GetCurrent());
        }
    }
};

} // namespace metrics

#endif // _METRIC_METRIC_DOUBLEHISTOGRAM_HPP
