#ifndef _METRIC_METRIC_UINTCONTER_HPP
#define _METRIC_METRIC_UINTCONTER_HPP

#include <metrics/imetric.hpp>

#include "ot.hpp"

namespace metrics
{
using OtUIntCounterPtr = otapi::unique_ptr<otapi::Counter<uint64_t>>;

class UIntCounter : public BaseMetric<uint64_t>
{
private:
    OtUIntCounterPtr m_counter;

public:
    UIntCounter(std::string&& name, std::string&& description, std::string&& unit)
        : BaseMetric<uint64_t>(std::move(name), std::move(description), std::move(unit))
        , m_counter(nullptr)
    {
    }

    UIntCounter(const UIntCounter&) = delete;
    UIntCounter& operator=(const UIntCounter&) = delete;
    UIntCounter(UIntCounter&&) = delete;
    UIntCounter& operator=(UIntCounter&&) = delete;

    ~UIntCounter() override = default;

    void create() override
    {
        m_counter = otapi::Provider::GetMeterProvider()
                        ->GetMeter(DEFAULT_METER_NAME)
                        ->CreateUInt64Counter(m_name, m_description, m_unit);
    }

    void update(uint64_t value) override
    {
        if (m_enabled)
        {
            m_counter->Add(value, otapi::RuntimeContext::GetCurrent());
        }
    }
};

} // namespace metrics

#endif // _METRIC_METRIC_UINTCONTER_HPP
