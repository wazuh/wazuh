#ifndef _I_METRICS_INSTRUMENTS_H
#define _I_METRICS_INSTRUMENTS_H

#include <cstdint>

namespace metrics_manager 
{

template <typename T>
class iCounter
{
public:
    virtual void addValue(const T& value) = 0;
};

template <typename T>
class iHistogram
{
public:
    virtual void recordValue(const T& value) = 0;
};

template <typename T>
class iGauge
{
public:
    virtual void setValue(const T& value) = 0;
};

} // namespace metrics_manager

#endif // _I_METRICS_INSTRUMENTS_H
