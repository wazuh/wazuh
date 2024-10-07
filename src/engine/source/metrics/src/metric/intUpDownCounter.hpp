#ifndef _METRIC_METRIC_INTUPDOWNCOUNTER_HPP
#define _METRIC_METRIC_INTUPDOWNCOUNTER_HPP

#include <metrics/imetric.hpp>

#include "metric/metric.hpp"
#include "ot.hpp"

namespace metrics
{
using OtIntUpDownCounterPtr = otapi::unique_ptr<otapi::UpDownCounter<int64_t>>;

class IntUpDownCounter : public BaseOtMetric<int64_t>
{
private:
    OtIntUpDownCounterPtr m_counter;

public:
    IntUpDownCounter(std::string&& name, std::string&& description, std::string&& unit)
        : BaseOtMetric<int64_t>(std::move(name), std::move(description), std::move(unit))
        , m_counter(nullptr)
    {
    }

    IntUpDownCounter(const IntUpDownCounter&) = delete;
    IntUpDownCounter& operator=(const IntUpDownCounter&) = delete;
    IntUpDownCounter(IntUpDownCounter&&) = delete;
    IntUpDownCounter& operator=(IntUpDownCounter&&) = delete;

    ~IntUpDownCounter() override = default;

    void otCreate() override
    {
        m_counter = otapi::Provider::GetMeterProvider()
                        ->GetMeter(DEFAULT_METER_NAME)
                        ->CreateInt64UpDownCounter(m_name, m_description, m_unit);
    }

    void otDestroy() override { m_counter.reset(); }

    void otUpdate(int64_t value) override
    {
        if (m_counter)
        {
            m_counter->Add(value, otapi::RuntimeContext::GetCurrent());
        }
    }
};

} // namespace metrics

#endif // _METRIC_METRIC_INTUPDOWNCOUNTER_HPP
