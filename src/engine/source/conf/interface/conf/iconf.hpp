#ifndef _ICONF_HPP
#define _ICONF_HPP

#include <string>

namespace conf
{

/**
 * @brief Interface for the configuration manager.
 *
 * @tparam ConfDriver implementation of the configuration manager.
 */
template<typename ConfDriver>
class IConf
{
private:
    ConfDriver m_confDriver;

public:
    /**
     * @brief Construct a new IConf object.
     *
     * @param driver The implementation of the configuration manager.
     */
    IConf(ConfDriver&& driver)
        : m_confDriver(std::move(driver))
    {
    }

    /**
     * @brief Get the value of an option.
     *
     * @tparam T The type of the option.
     * @param key The key of the option.
     * @return T The value of the option.
     */
    template<typename T>
    T get(const std::string& key) const
    {
        return m_confDriver.template get<T>(key);
    }

    /**
     * @brief Save the current options to a configuration file.
     *
     * @param path The path to save the configuration to.
     *
     */
    void saveConfiguration(const std::string& path = "") const { m_confDriver.saveConfiguration(path); }

    /**
     * @brief Put a value in the configuration.
     *
     * @param key The key of the option.
     * @param value The value to put in the option.
     */
    void put(const std::string& key, const std::string& value) { m_confDriver.put(key, value); }

    /**
     * @brief Get the configuration as a string.
     *
     * @return std::string The configuration.
     */
    std::string getConfiguration() const { return m_confDriver.getConfiguration(); }
};

} // namespace conf

#endif // _ICONF_HPP
