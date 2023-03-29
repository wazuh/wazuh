#ifndef _INSTRUMENT_COLLECTION_H
#define _INSTRUMENT_COLLECTION_H

#include <map>
#include <string>
#include <memory>
#include <functional>

namespace metrics_manager
{

template <typename T, typename U>
class InstrumentCollection
{
public:
    std::shared_ptr<T> getInstrument(
        const std::string& name,
        const std::function<U()>& createFunction,
        const std::function<void(const std::shared_ptr<T>&)>& onCreateFunction=[](const std::shared_ptr<T>&){}) 
    {
        auto it = m_instruments.find(name);
        if (m_instruments.end() == it)
        {
            auto newCounter = createFunction();

            std::shared_ptr<T> newInstrument = 
                std::make_shared<T>(std::move(newCounter));

            m_instruments.insert(
                std::make_pair<std::string, std::shared_ptr<T>>(
                    std::string(name),
                    std::move(newInstrument)));

            onCreateFunction(m_instruments[name]);
        }

        return m_instruments[name];
    }

private:
    std::map<std::string, std::shared_ptr<T>> m_instruments;
};

} // namespace metrics

#endif // _INSTRUMENT_COLLECTION_H
