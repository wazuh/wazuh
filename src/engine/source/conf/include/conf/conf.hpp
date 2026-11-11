// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CONFIG_CONFIG_HPP
#define _CONFIG_CONFIG_HPP

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

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

inline constexpr std::string_view LOG_MODULE_NAME = "Config"; ///< Log module name for configuration

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
        if (!result.empty())
        {
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
 * @brief Inclusive range of the values an integer configuration unit accepts.
 */
struct Range
{
    int64_t min; ///< Smallest allowed value.
    int64_t max; ///< Largest allowed value.
};

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
    std::unordered_map<std::string, Range> m_ranges;                                  ///< Range of each ranged unit.
    std::vector<std::function<void(const Conf&)>> m_rangeChecks; ///< One check per ranged unit, run by load().
    /// One type check per unit, run by load() before the range checks.
    std::vector<std::function<void(const Conf&)>> m_typeChecks;

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
     * Checks that the environment variable and the file value of every registered key parse as the key's type,
     * then the effective value (environment variable, else file, else default) of every key registered with a
     * range. The `-t` test and a start call it alike.
     *
     * @throw std::runtime_error If the configuration is invalid (a type or a range).
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
        m_typeChecks.emplace_back([keyStr = std::string(key)](const Conf& conf) { conf.checkType<T>(keyStr); });
    }

    /**
     * @brief Add a new integer configuration unit with an allowed range.
     *
     * The effective value of the unit (environment variable, else file, else default; see get()) is checked
     * against the range by load(), which throws when it is outside: a start and the `-t` test run the same check.
     *
     * @tparam T The integer type of the configuration (int, int64_t or size_t).
     * @param key The key of the configuration.
     * @param env The environment variable name.
     * @param defaultValue The default value of the configuration; it must be inside the range.
     * @param range The inclusive range of allowed values.
     * @throw std::invalid_argument If the key or environment variable is empty or already registered.
     * @throw std::logic_error If the range is empty, negative for an unsigned unit, or excludes the default.
     */
    template<typename T>
    void addUnit(std::string_view key, std::string_view env, const T& defaultValue, const Range& range)
    {
        static_assert(std::is_same_v<T, int> || std::is_same_v<T, int64_t> || std::is_same_v<T, size_t>,
                      "Only integer configuration units take a range");

        if (range.min > range.max)
        {
            throw std::logic_error(fmt::format("The range of the key '{}' is empty.", key));
        }
        if constexpr (std::is_same_v<T, size_t>)
        {
            if (range.min < 0)
            {
                throw std::logic_error(fmt::format("The range of the unsigned key '{}' cannot be negative.", key));
            }
        }
        if (!inRange(defaultValue, range))
        {
            throw std::logic_error(fmt::format("The default value of the key '{}' is outside its range.", key));
        }

        addUnit<T>(key, env, defaultValue);
        m_ranges.emplace(std::string(key), range);
        m_rangeChecks.emplace_back([keyStr = std::string(key), range](const Conf& conf)
                                   { conf.checkRange<T>(keyStr, range); });
    }

    /**
     * @brief Get the allowed range of a key, if it has one.
     *
     * @param key The key of the configuration.
     * @return std::optional<Range> The range, or std::nullopt when the key has none (or is not registered).
     */
    std::optional<Range> getRange(std::string_view key) const
    {
        const auto it = m_ranges.find(std::string(key));
        if (it == m_ranges.end())
        {
            return std::nullopt;
        }
        return it->second;
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
        return resolve<T>(key).value;
    }

private:
    /// Where an effective value comes from.
    enum class Source
    {
        ENVIRONMENT,
        FILE,
        DEFAULT
    };

    /// An effective value and its source.
    template<typename T>
    struct Resolved
    {
        T value;
        Source source;
    };

    template<typename T>
    static bool inRange(const T& value, const Range& range)
    {
        if constexpr (std::is_same_v<T, size_t>)
        {
            // range.min >= 0 is enforced by addUnit()
            return value >= static_cast<size_t>(range.min) && value <= static_cast<size_t>(range.max);
        }
        else
        {
            return static_cast<int64_t>(value) >= range.min && static_cast<int64_t>(value) <= range.max;
        }
    }

    /**
     * @brief Describe the values a unit of type T accepts, for an error message.
     */
    template<typename T>
    static std::string expectedType()
    {
        if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t> || std::is_same_v<T, size_t>)
        {
            return fmt::format(
                "an integer from {} to {}", std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            return "'true' or 'false'";
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>)
        {
            return "a comma-separated list without brackets";
        }
        else
        {
            return "a string";
        }
    }

    /**
     * @brief Parse a value of the configuration file as T.
     *
     * @throw std::runtime_error If the value does not parse as T.
     */
    template<typename T>
    static T parseFileValue(std::string_view key, const std::string& rawValue)
    {
        if constexpr (std::is_same_v<T, std::string>)
        {
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
            return lowerValue == "true";
        }
        else if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t> || std::is_same_v<T, size_t>)
        {
            if (const auto value = internal::parseInteger<T>(rawValue))
            {
                return *value;
            }
            throw std::runtime_error(fmt::format(
                "Invalid configuration type for key '{}'. Expected {}, got '{}'.", key, expectedType<T>(), rawValue));
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>)
        {
            // Disallow bracket notation at the beginning and end (JSON style)
            if (!rawValue.empty() && rawValue.front() == '[' && rawValue.back() == ']')
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
        else
        {
            throw std::runtime_error("The type is not supported.");
        }
    }

    /**
     * @brief Check that the environment variable and the file value of a key parse as its type.
     *
     * A value that does not parse is refused as an out-of-range one is, instead of falling back to the next source.
     *
     * @throw std::runtime_error Naming the key, the value, where it comes from and what the key accepts.
     */
    template<typename T>
    void checkType(const std::string& key) const
    {
        const auto& unit = m_units.at(key);
        const auto typeError = [&key](const std::string& source, const std::string& value)
        {
            return std::runtime_error(fmt::format(
                "Invalid value for key '{}' from the {}: '{}'. Expected {}.", key, source, value, expectedType<T>()));
        };

        if (const char* envValue = std::getenv(unit->getEnv().c_str()))
        {
            try
            {
                static_cast<void>(unit->template getEnvValue<T>());
            }
            catch (const std::exception&)
            {
                throw typeError(fmt::format("environment variable '{}'", unit->getEnv()), envValue);
            }
        }

        if (const auto it = m_fileConfig.find(key); it != m_fileConfig.end())
        {
            try
            {
                static_cast<void>(parseFileValue<T>(key, it->second));
            }
            catch (const std::exception&)
            {
                throw typeError("internal options file", it->second);
            }
        }
    }

    /**
     * @brief Check the effective value of a key against its range.
     *
     * @throw std::runtime_error Naming the key, the value, where it comes from and the allowed range.
     */
    template<typename T>
    void checkRange(const std::string& key, const Range& range) const
    {
        const auto resolved = resolve<T>(key);
        if (inRange(resolved.value, range))
        {
            return;
        }

        std::string source;
        switch (resolved.source)
        {
            case Source::ENVIRONMENT:
                source = fmt::format("environment variable '{}'", m_units.at(key)->getEnv());
                break;
            case Source::FILE: source = "internal options file"; break;
            default: source = "default value"; break;
        }

        throw std::runtime_error(fmt::format("Invalid value for key '{}' from the {}: '{}'. Allowed range: {} to {}.",
                                             key,
                                             source,
                                             resolved.value,
                                             range.min,
                                             range.max));
    }

    /**
     * @brief Resolve the effective value of the key and its source (see get()).
     */
    template<typename T>
    Resolved<T> resolve(std::string_view key) const
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
                LOG_DEBUG("[{}] Using configuration key '{}' from environment variable '{}': '{}'",
                          LOG_MODULE_NAME,
                          key,
                          unit->getEnv(),
                          toStr<T>(envValue.value()));
                return {envValue.value(), Source::ENVIRONMENT};
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[{}] Failed to retrieve or convert environment variable for key '{}': {}. "
                        " Falling back to file or default value.",
                        LOG_MODULE_NAME,
                        key,
                        e.what());
        }

        // 2. Configuration file
        auto it = m_fileConfig.find(key.data());
        if (it != m_fileConfig.end())
        {
            const auto& rawValue = it->second;
            try
            {
                auto value = parseFileValue<T>(key, rawValue);
                LOG_DEBUG("[{}] Using configuration key '{}' from file: '{}'", LOG_MODULE_NAME, key, rawValue);
                return {std::move(value), Source::FILE};
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("[{}] Failed to convert value '{}' for key '{}': {}. "
                            "Using default value",
                            LOG_MODULE_NAME,
                            rawValue,
                            key,
                            e.what());
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

        LOG_DEBUG("[{}] Using configuration key '{}' from default: '{}'", LOG_MODULE_NAME, key, strVal);

        return {value, Source::DEFAULT};
    }
};

} // namespace conf

#endif // _CONFIG_CONFIG_HPP
