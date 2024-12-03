#ifndef _CONFIG_CONFIG_HPP
#define _CONFIG_CONFIG_HPP

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/logging.hpp>

#include <conf/apiLoader.hpp>
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
} // namespace
/**
 * @brief Engine configuration.
 */
class Conf final
{
private:
    json::Json m_apiConfig; ///< The configuration from the framework API.
    std::unordered_map<std::string, std::shared_ptr<internal::BaseUnitConf>> m_units; ///< The configuration units.
    std::shared_ptr<IApiLoader> m_apiLoader;                                          ///< The API loader.

    /**
     * @brief Validate the configuration
     *
     * Comparting the configuration types with the default value types.
     * @throw std::runtime_error If the configuration is invalid.
     */
    void validate(const json::Json& config) const;

public:
    Conf() = delete;

    /**
     * @brief Create a new Engine Config
     *
     * This object is used to load and validate the configuration.
     */
    explicit Conf(std::shared_ptr<IApiLoader> apiLoader);

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
        if (!m_apiConfig.isNull())
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

        // Search for the configuration API,if not found, return the default value
        if constexpr (std::is_same_v<T, std::string>)
        {
            const auto value = m_apiConfig.getString(key.data()).value_or(unit->template getDefaultValue<T>());
            const auto org = m_apiConfig.getString(key.data()).has_value() ? "API" : "default";
            LOG_DEBUG("Using configuration key '{}' from {}: '{}'", key, org, value);
            return value;
        }
        else if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t>)
        {
            const auto value = m_apiConfig.getIntAsInt64(key.data()).value_or(unit->template getDefaultValue<T>());
            const auto org = m_apiConfig.getIntAsInt64(key.data()).has_value() ? "API" : "default";
            LOG_DEBUG("Using configuration key '{}' from {}: '{}'", key, org, value);
            return value;
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>)
        {
            auto jArr = m_apiConfig.getArray(key.data());
            if (!jArr)
            {
                auto value = unit->template getDefaultValue<T>();
                LOG_DEBUG("Using configuration key '{}' from default: '{}'", key, toStr<T>(value));
                return value;
            }
            std::vector<std::string> result;
            for (const auto& item : jArr.value())
            {
                result.push_back(item.getString().value_or("ERROR VALUE"));
            }
            LOG_DEBUG("Using configuration key '{}' from API: '{}'", key, toStr<T>(result));
            return result;
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            auto value = m_apiConfig.getBool(key.data()).value_or(unit->template getDefaultValue<T>());
            const auto org = m_apiConfig.getBool(key.data()).has_value() ? "API" : "default";
            LOG_DEBUG("Using configuration key '{}' from {}: '{}'", key, org, value);
            return value;
        }

        throw std::runtime_error("The type is not supported.");
    }
};

} // namespace conf

#endif // _CONFIG_CONFIG_HPP
