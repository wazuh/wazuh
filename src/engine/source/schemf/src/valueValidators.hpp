#ifndef _SCHEMF_VALIDATORS_HPP
#define _SCHEMF_VALIDATORS_HPP

#include <hlp/hlp.hpp>
#include <schemf/ivalidator.hpp>

/**
 * @brief Value validator factories for schema field types.
 */
namespace schemf::validators
{

/** @brief Validator that checks if a JSON value is a boolean. */
inline ValueValidator getBoolValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isBool())
        {
            return base::Error {"Value is not a boolean"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a short (int8 range). */
inline ValueValidator getShortValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isInt() || !value.isInt64())
        {
            return base::Error {"Value is not an integer"};
        }

        auto val = value.getInt().value();

        if (val < std::numeric_limits<int8_t>::min() || val > std::numeric_limits<int8_t>::max())
        {
            return base::Error {"Value not in range for byte"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is an integer. */
inline ValueValidator getIntegerValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isInt())
        {
            return base::Error {"Value is not an integer"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a long (int64). */
inline ValueValidator getLongValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isInt64())
        {
            return base::Error {"Value is not a long"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a float. */
inline ValueValidator getFloatValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isFloat())
        {
            return base::Error {"Value is not a float"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a double. */
inline ValueValidator getDoubleValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isDouble())
        {
            return base::Error {"Value is not a double"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is an unsigned long (uint64). */
inline ValueValidator getUnsignedLongValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isUint64())
        {
            return base::Error {"Value is not an unsigned long"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a string. */
inline ValueValidator getStringValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a valid date string. */
inline ValueValidator getDateValidator()
{
    // TODO parametrize date format
    auto params = hlp::Params {};
    params.options.emplace_back("%Y-%m-%dT%H:%M:%SZ");
    auto dateParser = hlp::parsers::getDateParser(params);
    return [dateParser](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        auto val = value.getString().value();
        auto res = dateParser(val);
        if (!res.success())
        {
            return base::Error {"Invalid date"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a valid IP address string. */
inline ValueValidator getIpValidator()
{
    auto ipParser = hlp::parsers::getIPParser({});
    return [ipParser](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        auto val = value.getString().value();
        auto res = ipParser(val);

        if (!res.success() || !res.remaining().empty())
        {
            return base::Error {"Invalid IP"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is a valid base64 binary string. */
inline ValueValidator getBinaryValidator()
{
    auto binaryParser = hlp::parsers::getBinaryParser({});
    return [binaryParser](const json::Json& value) -> base::OptError
    {
        if (!value.isString())
        {
            return base::Error {"Value is not a string"};
        }

        auto val = value.getString().value();
        auto res = binaryParser(val);

        if (!res.success())
        {
            return base::Error {"Invalid binary"};
        }

        return base::noError();
    };
}

/** @brief Validator that checks if a JSON value is an object. */
inline ValueValidator getObjectValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        if (!value.isObject())
        {
            return base::Error {"Value is not an object"};
        }

        return base::noError();
    };
}

/** @brief Validator that always returns an error (incompatible type). */
inline ValueValidator getIncompatibleValidator()
{
    return [](const json::Json& value) -> base::OptError
    {
        return base::Error {"Incompatible type"};
    };
}

} // namespace schemf::validators

#endif // _SCHEMF_VALIDATORS_HPP
