#ifndef _SCHEMVAL_VALIDATORS_HPP
#define _SCHEMVAL_VALIDATORS_HPP

#include <hlp/hlp.hpp>
#include <schemval/ivalidator.hpp>

namespace schemval::validators
{

inline RuntimeValidator getBoolValidator()
{
    return [](const json::Json& value)
    {
        return value.isBool();
    };
}

inline RuntimeValidator getByteValidator()
{
    return [](const json::Json& value)
    {
        if (!value.isInt())
        {
            return false;
        }

        auto val = value.getInt().value();

        return val >= std::numeric_limits<int8_t>::min() && val <= std::numeric_limits<int8_t>::max();
    };
}

inline RuntimeValidator getIntegerValidator()
{
    return [](const json::Json& value)
    {
        return value.isInt();
    };
}

inline RuntimeValidator getLongValidator()
{
    return [](const json::Json& value)
    {
        return value.isInt64();
    };
}

inline RuntimeValidator getFloatValidator()
{
    return [](const json::Json& value)
    {
        return value.isFloat();
    };
}

inline RuntimeValidator getDoubleValidator()
{
    return [](const json::Json& value)
    {
        return value.isDouble();
    };
}

inline RuntimeValidator getStringValidator()
{
    return [](const json::Json& value)
    {
        return value.isString();
    };
}

inline RuntimeValidator getDateValidator()
{
    // TODO parametrize date format
    auto params = hlp::Params {};
    params.options.emplace_back("%Y-%m-%dT%H:%M:%SZ");
    auto dateParser = hlp::parsers::getDateParser(params);
    return [dateParser](const json::Json& value)
    {
        if (!value.isString())
        {
            return false;
        }

        auto val = value.getString().value();
        auto res = dateParser(val);
        return res.success();
    };
}

inline RuntimeValidator getIpValidator()
{
    auto ipParser = hlp::parsers::getIPParser({});
    return [ipParser](const json::Json& value)
    {
        if (!value.isString())
        {
            return false;
        }

        auto val = value.getString().value();
        auto res = ipParser(val);
        return res.success();
    };
}

inline RuntimeValidator getBinaryValidator()
{
    auto binaryParser = hlp::parsers::getBinaryParser({});
    return [binaryParser](const json::Json& value)
    {
        if (!value.isString())
        {
            return false;
        }

        auto val = value.getString().value();
        auto res = binaryParser(val);
        return res.success();
    };
}

} // namespace schemval::validators

#endif // _SCHEMVAL_VALIDATORS_HPP
