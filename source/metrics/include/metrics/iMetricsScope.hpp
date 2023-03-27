#ifndef _I_METRICS_SCOPE_H
#define _I_METRICS_SCOPE_H

#include <metrics/IMetricsInstruments.hpp>

namespace metrics_manager 
{

class IMetricsScope 
{
public:
    virtual std::shared_ptr<instruments::iCounter<double>> getCounterDouble(const std::string& name) = 0;
    virtual std::shared_ptr<instruments::iCounter<uint64_t>> getCounterInteger(const std::string& name) = 0;
/*
// Opcion 1
    virtual InstrumentHandler getCounterDouble(const std::string& name) = 0;
    virtual InstrumentHandler getCounterInteger(const std::string& name) = 0;
    virtual InstrumentHandler getHistogram(const std::string& name) = 0;    


// Opcion 2
    virtual InstrumentHandler<CounterDouble> getCounterDouble(const std::string& name) = 0;
    virtual InstrumentHandler<CounterInteger> getCounterInteger(const std::string& name) = 0;
    virtual InstrumentHandler<Histogram> getHistogram(const std::string& name) = 0;    


// Opcion 3
    virtual CounterDouble   getCounterDouble(const std::string& name) = 0;
    virtual CounterInteger  getCounterInteger(const std::string& name) = 0;
    virtual Histogram       getHistogram(const std::string& name) = 0;    


// Opcion 4
CounterDouble:public InstrumentHandler;
CounterInteger:public InstrumentHandler;
Histogram::public InstrumentHandler;
    virtual CounterDouble getCounterDouble(const std::string& name) = 0;
    virtual CounterInteger getCounterInteger(const std::string& name) = 0;
    virtual Histogram getHistogram(const std::string& name) = 0;    
*/
};

} // namespace metrics_manager

#endif // _I_METRICS_SCOPE_H
