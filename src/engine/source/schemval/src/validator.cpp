#include "validator.hpp"

#include <hlp/hlp.hpp>

#include "validators.hpp"

using namespace schemval::validators;
using SType = schemf::Type;
using JType = json::Json::Type;

namespace schemval
{

Validator::Validator(const std::shared_ptr<schemf::ISchema>& schema)
{
    if (schema == nullptr)
    {
        throw std::runtime_error("Validator Schema cannot be null");
    }
    m_schema = schema;

    // Build table
    m_entries.emplace(SType::BOOLEAN, Entry {getBoolValidator(), JType::Boolean});
    m_entries.emplace(SType::BYTE, Entry {getByteValidator(), JType::Number});
    m_entries.emplace(SType::SHORT, Entry {getByteValidator(), JType::Number});
    m_entries.emplace(SType::INTEGER, Entry {getIntegerValidator(), JType::Number});
    m_entries.emplace(SType::LONG, Entry {getLongValidator(), JType::Number});
    m_entries.emplace(SType::FLOAT, Entry {getFloatValidator(), JType::Number});
    m_entries.emplace(SType::HALF_FLOAT, Entry {getFloatValidator(), JType::Number});
    m_entries.emplace(SType::SCALED_FLOAT, Entry {getFloatValidator(), JType::Number});
    m_entries.emplace(SType::DOUBLE, Entry {getDoubleValidator(), JType::Number});
    m_entries.emplace(SType::KEYWORD, Entry {getStringValidator(), JType::String});
    m_entries.emplace(SType::TEXT, Entry {getStringValidator(), JType::String});
    m_entries.emplace(SType::DATE, Entry {getDateValidator(), JType::String});
    m_entries.emplace(SType::DATE_NANOS, Entry {nullptr, JType::String});
    m_entries.emplace(SType::IP, Entry {getIpValidator(), JType::String});
    m_entries.emplace(SType::BINARY, Entry {getBinaryValidator(), JType::String});
    m_entries.emplace(SType::OBJECT, Entry {nullptr, JType::Object});
    m_entries.emplace(SType::NESTED, Entry {nullptr, JType::Object});
}

base::OptError Validator::validateItem(const DotPath& destPath, const ValidationToken& token, bool ignoreArray) const
{
    auto destType = m_schema->getType(destPath);

    switch (token.which())
    {
        case IS_JTYPE:
            if (!isCompatible(destType, std::get<JType>(token.getToken())))
            {
                return base::Error {fmt::format("Field '{}' of type '{}' is not compatible with the given type '{}'",
                                                destPath,
                                                schemf::typeToStr(destType),
                                                json::Json::typeToStr(std::get<JType>(token.getToken())))};
            }
            break;
        case IS_STYPE:
            // if destType is keyword or text, all string types are compatible
            if (destType == SType::KEYWORD || destType == SType::TEXT)
            {
                auto jType = getEntry(std::get<SType>(token.getToken())).jsonType;
                if (jType == json::Json::Type::String)
                {
                    break;
                }
            }

            if (destType != std::get<SType>(token.getToken()))
            {
                return base::Error {fmt::format("Field '{}' of type '{}' is not compatible with the given type '{}'",
                                                destPath,
                                                schemf::typeToStr(destType),
                                                schemf::typeToStr(std::get<SType>(token.getToken())))};
            }
            break;
        case IS_VALUE:
        {
            auto runtimeValidator = getRuntimeValidator(destPath, ignoreArray);
            if (!base::isError(runtimeValidator))
            {
                if (!base::getResponse<RuntimeValidator>(runtimeValidator)(std::get<json::Json>(token.getToken())))
                {
                    return base::Error {
                        fmt::format("Field '{}' of type '{}' is not compatible with the given value '{}'",
                                    destPath,
                                    schemf::typeToStr(destType),
                                    std::get<json::Json>(token.getToken()).str())};
                }
            }
            break;
        }
        default: break;
    }

    return base::noError();
}

base::OptError Validator::validate(const DotPath& destPath, const ValidationToken& token) const
{
    if (token.which() == IS_NONE)
    {
        return base::noError();
    }

    if (!m_schema->hasField(destPath))
    {
        return base::noError();
    }

    if (m_schema->isArray(destPath) && !token.isArray())
    {
        return base::Error {fmt::format("Field '{}' is an array", destPath)};
    }

    if (!m_schema->isArray(destPath) && token.isArray())
    {
        return base::Error {fmt::format("Field '{}' is not an array", destPath)};
    }

    return validateItem(destPath, token, false);
}

base::OptError Validator::validateArray(const DotPath& destPath, const ValidationToken& token) const
{
    if (token.which() == IS_NONE)
    {
        return base::noError();
    }

    if (!m_schema->hasField(destPath))
    {
        return base::noError();
    }

    if (!m_schema->isArray(destPath))
    {
        return base::Error {fmt::format("Field '{}' is not an array", destPath)};
    }

    if (token.isArray())
    {
        return base::Error {fmt::format("Array of arrays is not supported for field '{}'", destPath)};
    }

    return validateItem(destPath, token, true);
}

base::RespOrError<RuntimeValidator> Validator::getRuntimeValidator(const DotPath& destPath, bool ignoreArray) const
{
    if (!m_schema->hasField(destPath))
    {
        return base::Error {fmt::format("Field '{}' does not exist in schema", destPath)};
    }

    auto sType = m_schema->getType(destPath);
    auto validator = getEntry(sType).validator;

    if (validator == nullptr)
    {
        return base::Error {fmt::format("Field '{}' does not have a runtime validator", destPath)};
    }

    if (!ignoreArray && m_schema->isArray(destPath))
    {
        validator = [validator](const json::Json& value) -> bool
        {
            if (!value.isArray())
            {
                return false;
            }

            for (const auto& item : value.getArray().value())
            {
                if (!validator(item))
                {
                    return false;
                }
            }

            return true;
        };
    }

    return validator;
}

ValidationToken Validator::createToken(json::Json::Type type) const
{
    return ValidationToken(type);
}
ValidationToken Validator::createToken(schemf::Type type) const
{
    return ValidationToken(type);
}
ValidationToken Validator::createToken(const json::Json& value) const
{
    return ValidationToken(value);
}
ValidationToken Validator::createToken(const DotPath& path) const
{
    if (m_schema->hasField(path))
    {
        return ValidationToken(m_schema->getType(path), m_schema->isArray(path));
    }
    return ValidationToken {};
}
ValidationToken Validator::createToken() const
{
    return ValidationToken {};
}

} // namespace schemval
