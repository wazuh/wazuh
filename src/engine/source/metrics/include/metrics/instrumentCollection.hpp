#ifndef _METRICS_INSTRUMENT_COLLECTION_H
#define _METRICS_INSTRUMENT_COLLECTION_H

#include <functional>
#include <map>
#include <memory>
#include <string>

namespace metricsManager
{

/**
 * @brief Collection of Instruments. Held by Metrics Scope. Deals with registration, custom factory, and indexing.
 *
 * @tparam T Concrete Instrument Type. Wrapper of OpenTelemetry Internals.
 * @tparam U The OpenTelemetry Internal Instrument type.
 */
template<typename T, typename U>
class InstrumentCollection
{
public:
    std::shared_ptr<T> getInstrument(
        const std::string& name,
        const std::function<U()>& createFunction,
        const std::function<void(const std::shared_ptr<T>&)>& onCreateFunction = [](const std::shared_ptr<T>&) {})
    {
        auto it = m_instruments.find(name);
        if (m_instruments.end() == it)
        {
            auto newCounter = createFunction();

            std::shared_ptr<T> newInstrument = std::make_shared<T>(std::move(newCounter));

            m_instruments.insert(
                std::make_pair<std::string, std::shared_ptr<T>>(std::string(name), std::move(newInstrument)));

            onCreateFunction(m_instruments[name]);
        }

        return m_instruments[name];
    }

private:
    /**
     * @brief Mapping of concrete instruments by their respective name.
     */
    std::map<std::string, std::shared_ptr<T>> m_instruments;
};

} // namespace metricsManager

#endif // _METRICS_INSTRUMENT_COLLECTION_H
