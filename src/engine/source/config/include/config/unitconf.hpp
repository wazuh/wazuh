#ifndef _CONFIG_UNITCONF_HPP
#define _CONFIG_UNITCONF_HPP

#include <functional>
#include <optional>
#include <string>
#include <cxxabi.h>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>

namespace config::internal
{

template<typename T>
class UConf;

enum class UnitConfType : int8_t
{
    INTEGER,
    STRING,
    STRING_LIST,
    BOOL
};

/**
 * @brief Base class for the unit configuration.
 */
class BaseUnitConf : public std::enable_shared_from_this<BaseUnitConf>
{

private:
    /**
     * @brief Cast the unit config to a specific type.
     *
     * @tparam T The type to cast to. Must be derived from BaseUnitConf.
     * @throw std::runtime_error If the cast is not possible.
     * @return std::shared_ptr<BaseUnitConf> The casted config.
     */
    template<typename T>
    std::shared_ptr<T> as()
    {
        static_assert(std::is_base_of<BaseUnitConf, T>::value, "T must be derived from BaseUnitConf");
        auto ptr = std::dynamic_pointer_cast<T>(shared_from_this());

        if (!ptr)
        {
            throw std::runtime_error(fmt::format("Cannot cast the unit config to '{}'.", typeid(T).name()));
        }
        return ptr;
    }

    template<typename T>
    std::shared_ptr<const T> as() const
    {
        static_assert(std::is_base_of<BaseUnitConf, T>::value, "T must be derived from BaseUnitConf");
        auto ptr = std::dynamic_pointer_cast<const T>(shared_from_this());
        if (!ptr)
        {
            throw std::runtime_error(fmt::format("Cannot cast the unit config to '{}'.", typeid(T).name()));
        }
        return ptr;
    }

public:
    /**
     * @brief Get the Default Value of the configuration.
     *
     * @tparam T The type of the default value.
     * @throw std::runtime_error If the type is not the same.
     * @return const T& The default value. If the type is not the same, a runtime error is thrown.
     */
    template<typename T>
    const T& getDefaultValue() const
    {
        return as<UConf<T>>()->getDefaultValue();
    }

    /**
     * @brief Get the Environment Variable of the configuration.
     *
     * @tparam T The type of the environment variable.
     * @throw std::runtime_error If the type is not the same.
     * @return The value of the environment variable. If not set, std::nullopt is returned.
     */
    template<typename T>
    std::optional<T> getEnvValue() const
    {
        const auto ptr = as<UConf<T>>();
        return ptr->getEnvValue();
    }

    /**
     * @brief Get the type of the configuration.
     *
     * @return UnitConfType The type of the configuration.
     */
    virtual UnitConfType getType() const = 0;
};

template<typename T>
class UConf : public BaseUnitConf
{
private:
    std::string env;   ///< The environment variable where the configuration can be store
    T defaultValue;    ///< The default value of the configuration.
    UnitConfType type; ///< The type of the configuration.

public:
    UConf(std::string_view env, const T& defaultValue)
        : env(env)
        , defaultValue(defaultValue)
    {
        if (env.empty())
        {
            throw std::invalid_argument("The environment variable name cannot be empty.");
        }
        if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t>)
        {
            type = UnitConfType::INTEGER;
        }
        else if constexpr (std::is_same_v<T, std::string>)
        {
            type = UnitConfType::STRING;
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>)
        {
            type = UnitConfType::STRING_LIST;
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            type = UnitConfType::BOOL;
        }
        else
        {
            static_assert(false, "Invalid type");
        }
    }

    static std::shared_ptr<UConf<T>> make(std::string_view env, const T& defaultValue)
    {
        return std::make_shared<UConf<T>>(env, defaultValue);
    }

    const T& getDefaultValue() const { return defaultValue; }

    std::optional<T> getEnvValue() const
    {
        const auto pValue = std::getenv(env.c_str());
        if (pValue == nullptr)
        {
            return std::nullopt;
        }
        const auto value = std::string(pValue);

        if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t>)
        {
            std::string::size_type pos;
            try
            {
                const auto number = std::stoll(value, &pos);
                if (pos != value.size())
                {
                    throw std::runtime_error(
                        fmt::format("Invalid number value for environment variable '{}' (value: '{}').", env, value));
                }
                if constexpr (std::is_same_v<T, int>)
                {
                    if (number < std::numeric_limits<int>::min() || number > std::numeric_limits<int>::max())
                    {
                        throw std::runtime_error(fmt::format(
                            "Number value out of range for environment variable '{}' (value: '{}').", env, value));
                    }
                }
                return static_cast<T>(number);
            }
            catch (const std::invalid_argument& e)
            {
                throw std::runtime_error(
                    fmt::format("Invalid number value for environment variable '{}' (value: '{}').", env, value));
            }
            catch (const std::out_of_range& e)
            {
                throw std::runtime_error(
                    fmt::format("Number value out of range for environment variable '{}' (value: '{}').", env, value));
            }
        }
        else if constexpr (std::is_same_v<T, std::string>)
        {
            return value;
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>)
        {
            return base::utils::string::splitEscaped(value, ',', '\\');
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            if (base::utils::string::toLowerCase(value) == "true")
            {
                return true;
            }
            else if (base::utils::string::toLowerCase(value) == "false")
            {
                return false;
            }
            else
            {
                throw std::runtime_error(
                    fmt::format("Invalid boolean value for environment variable '{}' (value: '{}').", env, value));
            }
        }
        else
        {
            static_assert(false, "Invalid type");
        }
    }

    UnitConfType getType() const override { return type; }
};

} // namespace config

#endif // _CONFIG_UNITCONF_HPP
