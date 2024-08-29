#ifndef _CLI_CONF_HPP
#define _CLI_CONF_HPP

#include <algorithm>
#include <filesystem>
#include <fstream>

#include <CLI/CLI.hpp>

#include <base/utils/stringUtils.hpp>

/**
 * @brief Namespace for the configuration manager.
 *
 */
namespace conf
{
/**
 * @brief Class for managing the configuration of the application.
 *
 */
class CliConf
{
private:
    CLI::App_p m_app;

    /**
     * @brief Get the internal Option object from a key.
     *
     * modules are nested by dots.
     *
     * @param key The key of the option.
     * @return const CLI::Option* The internal option.
     */
    const CLI::Option* getOption(const std::string& key) const;

    /**
     * @brief Get the internal Option object from a key.
     *
     * modules are nested by dots.
     *
     * @param key The key of the option.
     * @return const CLI::Option* The internal option.
     */
    CLI::Option* getOption(const std::string& key);

public:
    /**
     * @brief Construct a new Cli Conf object from a CLI::App_p.
     *
     * @param app The CLI::App_p to use.
     */
    explicit CliConf(CLI::App_p app);

    /**
     * @brief Get the value of an option.
     *
     * @tparam T The type of the option.
     * @param key The key of the option.
     * @return T The value of the option.
     *
     * @throw std::runtime_error If the option does not exist or cannot be casted to T.
     */
    template<typename T>
    T get(const std::string& key) const
    {
        return getOption(key)->as<T>();
    }

    /**
     * @brief Save the current options to a configuration file.
     *
     * @param path The path to save the configuration to.
     *
     * @throw std::runtime_error If the configuration file cannot be opened.
     */
    void saveConfiguration(const std::string& path = "") const;

    /**
     * @brief Get the configuration as a string.
     *
     * @return std::string The configuration.
     */
    std::string getConfiguration() const;

    /**
     * @brief Put a value in the configuration.
     *
     * @param key The key of the option.
     * @param value The value to put in the option.
     *
     * @throw std::runtime_error If the option does not exist or cannot be assigned to.
     */
    void put(const std::string& key, const std::string& value);
};
} // namespace conf

#endif // _CLI_CONF_HPP
