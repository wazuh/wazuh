#ifndef _MOCK_METRICS_INSTRUMENT_HPP
#define _MOCK_METRICS_INSTRUMENT_HPP

#include <gmock/gmock.h>

#include <metrics/iMetricsInstruments.hpp>

template<typename T>
class MockCounter : public metricsManager::iCounter<T>
{
public:
    MOCK_METHOD(void, addValue, (const T& value), (override));
};

template<typename T>
class MockHistogram : public metricsManager::iHistogram<T>
{
public:
    MOCK_METHOD(void, recordValue, (const T& value), (override));
};

template<typename T>
class MockGauge : public metricsManager::iGauge<T>
{
public:
    MOCK_METHOD(void, setValue, (const T& value), (override));
};

#endif //_MOCK_METRICS_INSTRUMENT_HPP
