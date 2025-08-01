#ifndef _CONFIG_CONFIG_HPP
#define _CONFIG_CONFIG_HPP

#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/logging.hpp>

#include <conf/fileLoader.hpp>
#include <conf/unitconf.hpp>

namespace conf
{

namespace
{
template<typename U>
std::string toStr(const U& value)
{
    if constexpr (std::is_same_v<U, std::vector<std::string>>)
    {
        std::string result {};
        for (const auto& item : value)
        {
            result += item + ",";
        }
        result.pop_back(); // Remove the last comma
        return result;
    }

    if constexpr (std::is_same_v<U, bool>)
    {
        return value ? "true" : "false";
    }

    if constexpr (std::is_same_v<U, std::string>)
    {
        return value;
    }

    if constexpr (std::is_same_v<U, int> || std::is_same_v<U, int64_t>)
    {
        return fmt::format("{}", value);
    }

    throw std::runtime_error("The type is not supported.");
}

template<typename T>
T convert(const std::string& value);

template<>
inline int convert<int>(const std::string& value)
{
    return std::stoi(value);
}

template<>
inline int64_t convert<int64_t>(const std::string& value)
{
    return std::stoll(value);
}

template<>
inline bool convert<bool>(const std::string& value)
{
    return value == "true";
}

template<>
inline std::string convert<std::string>(const std::string& value)
{
    return value;
}

template<>
inline std::vector<std::string> convert<std::vector<std::string>>(const std::string& value)
{
    std::vector<std::string> result;
    std::istringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ','))
    {
        // Trim left
        item.erase(item.begin(), std::find_if(item.begin(), item.end(), [](unsigned char ch) {
            return !std::isspace(ch);
        }));

        // Trim right
        item.erase(std::find_if(item.rbegin(), item.rend(), [](unsigned char ch) {
            return !std::isspace(ch);
        }).base(), item.end());

        result.push_back(item);
    }
    return result;
}
} // namespace
/**
 * @brief Engine configuration.
 */
class Conf final
{
private:
    OptionMap m_fileConfig; ///< The configuration from the framework API.
    std::unordered_map<std::string, std::shared_ptr<internal::BaseUnitConf>> m_units; ///< The configuration units.
    std::shared_ptr<IFileLoader> m_fileLoader;                                          ///< The API loader.

    /**
     * @brief Validate the configuration
     *
     * Comparting the configuration types with the default value types.
     * @throw std::runtime_error If the configuration is invalid.
     */
    void validate(const OptionMap& config) const;

public:
    Conf() = delete;

    /**
     * @brief Create a new Engine Config
     *
     * This object is used to load and validate the configuration.
     */
    explicit Conf(std::shared_ptr<IFileLoader> fileLoader);

    /**
     * @brief Load the configuration from API and environment variables.
     *
     * @throw std::runtime_error If the configuration is invalid.
     * @throw std::runtime_error If cannot retrieve the configuration from the framework API.
     */
    void load();

    /**
     * @brief Add a new configuration unit.
     *
     * @tparam T The type of the configuration.
     * @param key The key of the configuration.
     * @param env The environment variable name.
     * @param defaultValue The default value of the configuration.
     * @throw std::invalid_argument If the key is empty.
     */
    template<typename T>
    void addUnit(std::string_view key, std::string_view env, const T& defaultValue)
    {
        if (!m_fileConfig.empty())
        {
            throw std::logic_error("The configuration is already loaded.");
        }

        if (key.empty())
        {
            throw std::invalid_argument("The key cannot be empty.");
        }

        // Check if the key or environment variable is already registered
        for (const auto& [k, unit] : m_units)
        {
            if (k == key)
            {
                throw std::invalid_argument(fmt::format("The key '{}' is already registered.", key));
            }
            if (unit->getEnv().compare(env) == 0)
            {
                throw std::invalid_argument(fmt::format("The environment variable '{}' is already registered.", env));
            }
        }
        m_units[key.data()] = internal::UConf<T>::make(env, defaultValue);
    }

    /**
     * @brief Get the value of the key.
     *
     * Priority order:
     * 1. Environment variable
     * 2. Configuration API
     * 3. Default value
     *
     * @tparam T type of the value.
     * @param key The key to get the value.
     * @return T The value of the key.
     * @throw std::runtime_error If the key is not found or is invalid value from the environment variable.
     */
    template<typename T>
    T get(std::string_view key) const
    {
        if (m_units.find(key.data()) == m_units.end())
        {
            throw std::runtime_error(
                fmt::format("The key '{}' is not found in the configuration options.", key.data()));
        }
        const auto unit = m_units.at(key.data());

        // Search for the environment variable, throw an error if the value is invalid
        if (const auto envValue = unit->template getEnvValue<T>())
        {
            LOG_DEBUG("Using configuration key '{}' fom environment variable '{}': '{}'.",
                      key,
                      unit->getEnv(),
                      toStr<T>(envValue.value()));
            return envValue.value();
        }

        // Search for the configuration file
        auto it = m_fileConfig.find(key.data());
        if (it != m_fileConfig.end())
        {
            try
            {
                auto value = convert<T>(it->second);
                LOG_DEBUG("Using configuration key '{}' from File: '{}'", key, toStr<T>(value));
                return value;
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(
                    fmt::format("Failed to convert value '{}' for key '{}': {}", it->second, key, e.what()));
            }
        }

        // Default value
        auto value = unit->template getDefaultValue<T>();
        LOG_DEBUG("Using configuration key '{}' from default: '{}'", key, toStr<T>(value));
        return value;
    }
};

} // namespace conf

#endif // _CONFIG_CONFIG_HPP
