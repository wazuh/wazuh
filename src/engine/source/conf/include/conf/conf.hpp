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
#include <base/utils/stringUtils.hpp>

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
        if (!result.empty()) {
            result.pop_back(); // Remove the last comma
        }
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

    if constexpr (std::is_same_v<U, int> || std::is_same_v<U, int64_t> || std::is_same_v<U, size_t>)
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
    OptionMap m_fileConfig; ///< The configuration from the file.
    bool m_loaded;          ///< Indicates if the configuration has been loaded.
    std::unordered_map<std::string, std::shared_ptr<internal::BaseUnitConf>> m_units; ///< The configuration units.
    std::shared_ptr<IFileLoader> m_fileLoader;                                        ///< The API loader.

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
     * @brief Load the configuration from File and environment variables.
     *
     * @throw std::runtime_error If the configuration is invalid.
     * @throw std::runtime_error If cannot retrieve the configuration from the File.
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

        // Cannot add new config after loads
        if (!m_fileConfig.empty())
        {
            throw std::logic_error("Cannot add new configuration unit after loading the configuration.");
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
     * 2. Configuration File
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

        const auto& unit = m_units.at(key.data());

        // 1. Environment variable
        try
        {
            if (const auto envValue = unit->template getEnvValue<T>())
            {
                LOG_DEBUG("Using configuration key '{}' from environment variable '{}': '{}'",
                          key,
                          unit->getEnv(),
                          toStr<T>(envValue.value()));
                return envValue.value();
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to retrieve or convert environment variable for key '{}': {}", key, e.what());
        }

        // 2. Configuration file
        auto it = m_fileConfig.find(key.data());
        if (it != m_fileConfig.end())
        {
            const auto& rawValue = it->second;
            try
            {
                if constexpr (std::is_same_v<T, std::string>)
                {
                    LOG_DEBUG("Using configuration key '{}' from file: '{}'", key, rawValue);
                    return rawValue;
                }
                else if constexpr (std::is_same_v<T, bool>)
                {
                    std::string lowerValue = rawValue;
                    std::transform(lowerValue.begin(),
                                   lowerValue.end(),
                                   lowerValue.begin(),
                                   [](unsigned char c) { return std::tolower(c); });

                    if (lowerValue != "true" && lowerValue != "false")
                    {
                        throw std::runtime_error("Expected 'true' or 'false' (case insensitive)");
                    }

                    bool value = (lowerValue == "true");
                    LOG_DEBUG("Using configuration key '{}' from file: '{}'", key, value);
                    return value;
                }
                else if constexpr (std::is_same_v<T, int>)
                {
                    if (!base::utils::string::isNumber(rawValue))
                    {
                        throw std::runtime_error(fmt::format(
                            "Invalid configuration type for key '{}'. Expected integer, got '{}'.", key, rawValue));
                    }

                    std::size_t pos = 0;
                    try
                    {
                        int value = std::stoi(rawValue, &pos);
                        if (pos != rawValue.size())
                        {
                            throw std::runtime_error(
                                fmt::format("Extra characters after int: '{}'", rawValue.substr(pos)));
                        }
                        LOG_DEBUG("Using configuration key '{}' from file: '{}'", key, value);
                        return value;
                    }
                    catch (const std::invalid_argument& e)
                    {
                        throw std::runtime_error(fmt::format(
                            "Invalid configuration type for key '{}'. Could not parse '{}'.", key, rawValue));
                    }
                    catch (const std::out_of_range& e)
                    {
                        throw std::runtime_error(
                            fmt::format("Invalid configuration type for key '{}'. Value out of range for int: '{}'.",
                                        key,
                                        rawValue));
                    }
                }
                else if constexpr (std::is_same_v<T, int64_t>)
                {
                    std::size_t pos = 0;
                    try
                    {
                        int64_t value = std::stoll(rawValue, &pos);
                        if (pos != rawValue.size())
                        {
                            throw std::runtime_error(
                                fmt::format("Extra characters after int64: '{}'", rawValue.substr(pos)));
                        }
                        LOG_DEBUG("Using configuration key '{}' from file: '{}'", key, value);
                        return value;
                    }
                    catch (const std::invalid_argument& e)
                    {
                        throw std::runtime_error(fmt::format(
                            "Invalid configuration type for key '{}'. Could not parse '{}'.", key, rawValue));
                    }
                    catch (const std::out_of_range& e)
                    {
                        throw std::runtime_error(
                            fmt::format("Invalid configuration type for key '{}'. Value out of range for int64: '{}'.",
                                        key,
                                        rawValue));
                    }
                }
                else if constexpr (std::is_same_v<T, size_t>)
                {
                    if (!base::utils::string::isNumber(rawValue))
                    {
                        throw std::runtime_error(
                            fmt::format("Invalid configuration type for key '{}'. Expected unsigned integer, got '{}'.",
                                        key,
                                        rawValue));
                    }

                    std::size_t pos = 0;
                    try
                    {
                        size_t value = std::stoull(rawValue, &pos);
                        if (pos != rawValue.size())
                        {
                            throw std::runtime_error(
                                fmt::format("Extra characters after size_t: '{}'", rawValue.substr(pos)));
                        }
                        LOG_DEBUG("Using configuration key '{}' from file: '{}'", key, value);
                        return value;
                    }
                    catch (const std::invalid_argument& e)
                    {
                        throw std::runtime_error(fmt::format(
                            "Invalid configuration type for key '{}'. Could not parse '{}'.", key, rawValue));
                    }
                    catch (const std::out_of_range& e)
                    {
                        throw std::runtime_error(
                            fmt::format("Invalid configuration type for key '{}'. Value out of range for size_t: '{}'.",
                                        key,
                                        rawValue));
                    }
                }
                else if constexpr (std::is_same_v<T, std::vector<std::string>>)
                {
                    // Disallow bracket notation at the beginning and end (JSON style)
                    if (rawValue.front() == '[' && rawValue.back() == ']')
                    {
                        throw std::runtime_error(fmt::format("Invalid value for key '{}': bracket notation "
                                                             "'[...]' is not allowed (value: '{}').",
                                                             key,
                                                             rawValue));
                    }

                    std::vector<std::string> result;
                    auto items = base::utils::string::splitEscaped(rawValue, ',', '\\');

                    for (auto& rawItem : items)
                    {
                        auto item = base::utils::string::trim(rawItem, " \t\r\n");
                        // Unescape characters
                        item = base::utils::string::unescapeString(item, '\\', ",\\", true);

                        result.emplace_back(std::move(item));
                    }

                    if (result.empty())
                    {
                        throw std::runtime_error(fmt::format("Invalid value for key '{}': empty list.", key));
                    }

                    return result;
                }
                throw std::runtime_error("The type is not supported.");
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("Failed to convert value '{}' for key '{}': {}", rawValue, key, e.what());
            }
        }

        // 3. Default value
        auto value = unit->template getDefaultValue<T>();

        const auto strVal = [&]() -> std::string
        {
            auto strVal = toStr<T>(value);
            if (strVal.empty())
            {
                return "<empty>";
            }
            return strVal;
        }();

        LOG_DEBUG("Using configuration key '{}' from default: '{}'", key, strVal);

        return value;
    }
};

} // namespace conf

#endif // _CONFIG_CONFIG_HPP
