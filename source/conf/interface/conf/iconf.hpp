#ifndef _ICONF_HPP
#define _ICONF_HPP

#include <string>

namespace conf
{

template<typename ConfDriver>
class IConf
{
private:
    ConfDriver m_confDriver;

public:
    IConf(ConfDriver&& driver)
        : m_confDriver(std::move(driver))
    {
    }

    template<typename T>
    T get(const std::string& key) const
    {
        return m_confDriver.template get<T>(key);
    }

    void saveConfiguration(const std::string& path = "") const
    {
        m_confDriver.saveConfiguration(path);
    }

    void put(const std::string& key, const std::string& value)
    {
        m_confDriver.put(key, value);
    }

    std::string getConfiguration() const { return m_confDriver.getConfiguration(); }
};

} // namespace conf

#endif // _ICONF_HPP
