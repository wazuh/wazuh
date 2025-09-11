#ifndef _SCHEMF_VALIDATORS_HPP
#define _SCHEMF_VALIDATORS_HPP

#include <hlp/hlp.hpp>
#include <schemf/ivalidator.hpp>

namespace schemf::validators
{

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

} // namespace schemf::validators

#endif // _SCHEMF_VALIDATORS_HPP
