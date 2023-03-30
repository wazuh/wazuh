#ifndef _I_METRICS_INSTRUMENTS_H
#define _I_METRICS_INSTRUMENTS_H

#include <cstdint>

namespace metrics_manager 
{

class iInstrument
{
public:
    virtual void setEnabledStatus(bool newStatus)
    {
        m_status = newStatus;
    }

    bool m_status = true;
};

template <typename T>
class iCounter : public iInstrument
{
public:
    virtual void addValue(const T& value) = 0;
};

template <typename T>
class iHistogram : public iInstrument
{
public:
    virtual void recordValue(const T& value) = 0;
};

template <typename T>
class iGauge : public iInstrument
{
public:
    virtual void setValue(const T& value) = 0;
};

} // namespace metrics_manager

#endif // _I_METRICS_INSTRUMENTS_H
