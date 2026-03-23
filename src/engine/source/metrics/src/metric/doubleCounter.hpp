#ifndef _METRIC_METRIC_DOUBLECOUNTER_HPP
#define _METRIC_METRIC_DOUBLECOUNTER_HPP

#include <metrics/imetric.hpp>

#include "metric/metric.hpp"
#include "ot.hpp"

namespace metrics
{
using OtDoubleCounterPtr = otapi::unique_ptr<otapi::Counter<double>>;

class DoubleCounter : public BaseOtMetric<double>
{
private:
    OtDoubleCounterPtr m_counter;

public:
    DoubleCounter(std::string&& name, std::string&& description, std::string&& unit)
        : BaseOtMetric<double>(std::move(name), std::move(description), std::move(unit))
        , m_counter(nullptr)
    {
    }

    DoubleCounter(const DoubleCounter&) = delete;
    DoubleCounter& operator=(const DoubleCounter&) = delete;
    DoubleCounter(DoubleCounter&&) = delete;
    DoubleCounter& operator=(DoubleCounter&&) = delete;

    ~DoubleCounter() override = default;

    void otCreate() override
    {
        m_counter = otapi::Provider::GetMeterProvider()
                        ->GetMeter(DEFAULT_METER_NAME)
                        ->CreateDoubleCounter(m_name, m_description, m_unit);
    }

    void otDestroy() override { m_counter.reset(); }

    void otUpdate(double value) override
    {
        if (m_counter)
        {
            m_counter->Add(value, otapi::RuntimeContext::GetCurrent());
        }
    }
};

} // namespace metrics

#endif // _METRIC_METRIC_DOUBLECOUNTER_HPP
