#ifndef _CONFIG_UNITCONF_HPP
#define _CONFIG_UNITCONF_HPP

#include <functional>
#include <optional>
#include <string>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/stringUtils.hpp>

namespace conf::internal
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
     * @return std::shared_ptr<const BaseUnitConf> The casted config.
     */
    template<typename T>
    std::shared_ptr<const T> as() const
    {
        static_assert(std::is_base_of<BaseUnitConf, T>::value, "T must be derived from BaseUnitConf");
        auto ptr = std::dynamic_pointer_cast<const T>(shared_from_this());
        if (!ptr)
        {
            // The type is not the same
            throw std::logic_error(
                fmt::format("Cannot cast the unit config to '{}', the type is not supported.", typeid(T).name()));
        }
        return ptr;
    }

protected:
    std::string m_env;   ///< The environment variable where the configuration can be store
    UnitConfType m_type; ///< The type of the configuration.

public:
    virtual ~BaseUnitConf() = default;

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
    UnitConfType getType() const { return m_type; }

    /**
     * @brief Get the environment variable name.
     *
     * @return const std::string& The environment variable name.
     */
    const std::string& getEnv() const { return m_env; }
};

template<typename T>
class UConf : public BaseUnitConf
{
private:
    T defaultValue; ///< The default value of the configuration.

    UConf(std::string_view env, const T& defaultValue)
        : defaultValue(defaultValue)
    {
        m_env = env;
        if (env.empty())
        {
            throw std::invalid_argument("The environment variable name cannot be empty.");
        }
        setType();
    }

    void setType()
    {
        if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int64_t>)
        {
            m_type = UnitConfType::INTEGER;
        }
        else if constexpr (std::is_same_v<T, std::string>)
        {
            m_type = UnitConfType::STRING;
        }
        else if constexpr (std::is_same_v<T, std::vector<std::string>>)
        {
            m_type = UnitConfType::STRING_LIST;
        }
        else if constexpr (std::is_same_v<T, bool>)
        {
            m_type = UnitConfType::BOOL;
        }
        else
        {
            throw std::invalid_argument(fmt::format("Invalid type '{}' for the configuration.", typeid(T).name()));
        }
    }

public:
    static std::shared_ptr<UConf<T>> make(std::string_view env, const T& defaultValue)
    {
        // Create an instance of UConf directly, bypassing make_shared since constructor is private
        std::shared_ptr<UConf<T>> instance(new UConf<T>(env, defaultValue));
        return instance;
    }

    const T& getDefaultValue() const { return defaultValue; }

    std::optional<T> getEnvValue() const
    {
        const auto pValue = std::getenv(m_env.c_str());
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
                // check for whitespace
                if (std::any_of(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c); }))
                {
                    throw std::runtime_error(
                        fmt::format("Invalid number value for environment variable '{}' (value: '{}').", m_env, value));
                }
                // check for invalid characters
                const auto number = std::stoll(value, &pos);
                if (pos != value.size())
                {
                    throw std::runtime_error(
                        fmt::format("Invalid number value for environment variable '{}' (value: '{}').", m_env, value));
                }
                if constexpr (std::is_same_v<T, int>)
                {
                    if (number < std::numeric_limits<int>::min() || number > std::numeric_limits<int>::max())
                    {
                        throw std::runtime_error(fmt::format(
                            "Number value out of range for environment variable '{}' (value: '{}').", m_env, value));
                    }
                }
                return static_cast<T>(number);
            }
            catch (const std::invalid_argument& e)
            {
                throw std::runtime_error(
                    fmt::format("Invalid number value for environment variable '{}' (value: '{}').", m_env, value));
            }
            catch (const std::out_of_range& e)
            {
                throw std::runtime_error(fmt::format(
                    "Number value out of range for environment variable '{}' (value: '{}').", m_env, value));
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
                    fmt::format("Invalid boolean value for environment variable '{}' (value: '{}').", m_env, value));
            }
        }
        else
        {
            throw std::logic_error("Invalid type for the configuration.");
        }
    }
};

} // namespace conf::internal

#endif // _CONFIG_UNITCONF_HPP
