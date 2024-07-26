#include "validator.hpp"
#include "valueValidators.hpp"

#include <fmt/format.h>

namespace schemf
{

void Schema::Validator::registerCompatibles()
{
    m_compatibles.emplace(Type::BOOLEAN,
                          ValidationInfo {json::Json::Type::Boolean, validators::getBoolValidator(), {}});
    m_compatibles.emplace(Type::BYTE,
                          ValidationInfo {json::Json::Type::Number,
                                          validators::getShortValidator(),
                                          {{Type::INTEGER, true}, {Type::LONG, true}, {Type::SHORT, false}}});
    m_compatibles.emplace(Type::SHORT,
                          ValidationInfo {json::Json::Type::Number,
                                          validators::getShortValidator(),
                                          {{Type::INTEGER, true}, {Type::LONG, true}, {Type::BYTE, false}}});
    m_compatibles.emplace(Type::INTEGER,
                          ValidationInfo {json::Json::Type::Number,
                                          validators::getIntegerValidator(),
                                          {{Type::LONG, true}, {Type::SHORT, false}, {Type::BYTE, false}}});
    m_compatibles.emplace(Type::LONG,
                          ValidationInfo {json::Json::Type::Number,
                                          validators::getLongValidator(),
                                          {{Type::INTEGER, false}, {Type::SHORT, false}, {Type::BYTE, false}}});
    m_compatibles.emplace(
        Type::FLOAT,
        ValidationInfo {json::Json::Type::Number,
                        validators::getFloatValidator(),
                        {{Type::DOUBLE, true}, {Type::HALF_FLOAT, false}, {Type::SCALED_FLOAT, false}}});
    m_compatibles.emplace(Type::HALF_FLOAT,
                          ValidationInfo {json::Json::Type::Number,
                                          validators::getFloatValidator(),
                                          {{Type::FLOAT, false}, {Type::DOUBLE, true}, {Type::SCALED_FLOAT, false}}});
    m_compatibles.emplace(Type::SCALED_FLOAT,
                          ValidationInfo {json::Json::Type::Number,
                                          validators::getFloatValidator(),
                                          {{Type::FLOAT, false}, {Type::HALF_FLOAT, false}, {Type::DOUBLE, true}}});
    m_compatibles.emplace(
        Type::DOUBLE,
        ValidationInfo {json::Json::Type::Number,
                        validators::getDoubleValidator(),
                        {{Type::FLOAT, false}, {Type::HALF_FLOAT, false}, {Type::SCALED_FLOAT, false}}});
    m_compatibles.emplace(Type::KEYWORD,
                          ValidationInfo {json::Json::Type::String,
                                          validators::getStringValidator(),
                                          {{Type::TEXT, false},
                                           {Type::DATE, false},
                                           {Type::DATE_NANOS, false},
                                           {Type::IP, false},
                                           {Type::BINARY, false}}});
    m_compatibles.emplace(Type::TEXT,
                          ValidationInfo {json::Json::Type::String,
                                          validators::getStringValidator(),
                                          {{Type::KEYWORD, false},
                                           {Type::DATE, false},
                                           {Type::DATE_NANOS, false},
                                           {Type::IP, false},
                                           {Type::BINARY, false}}});
    m_compatibles.emplace(Type::DATE,
                          ValidationInfo {json::Json::Type::String,
                                          validators::getDateValidator(),
                                          {{Type::KEYWORD, true}, {Type::TEXT, true}}});
    m_compatibles.emplace(Type::DATE_NANOS,
                          ValidationInfo {json::Json::Type::String,
                                          validators::getStringValidator(),
                                          {{Type::KEYWORD, true}, {Type::TEXT, true}}});
    m_compatibles.emplace(Type::IP,
                          ValidationInfo {json::Json::Type::String,
                                          validators::getIpValidator(),
                                          {{Type::KEYWORD, true}, {Type::TEXT, true}}});
    m_compatibles.emplace(Type::BINARY,
                          ValidationInfo {json::Json::Type::String,
                                          validators::getBinaryValidator(),
                                          {{Type::KEYWORD, true}, {Type::TEXT, true}}});
    m_compatibles.emplace(Type::OBJECT,
                          ValidationInfo {json::Json::Type::Object, validators::getObjectValidator(), {}});
    m_compatibles.emplace(Type::NESTED,
                          ValidationInfo {json::Json::Type::Object, validators::getObjectValidator(), {}});
    m_compatibles.emplace(Type::GEO_POINT,
                          ValidationInfo {json::Json::Type::Object, validators::getObjectValidator(), {}});
}

base::RespOrError<ValidationResult> Schema::Validator::validate(const DotPath& name, const JTypeToken& token) const
{
    const auto& entry = m_compatibles.at(m_schema.getType(name));

    if (entry.type != token.type())
    {
        return base::Error {fmt::format("Operation expects a JSON type '{}', but field '{}' is of JSON type '{}'",
                                        json::Json::typeToStr(token.type()),
                                        name,
                                        json::Json::typeToStr(entry.type))};
    }

    // When validating json types, if the schema type has a validator, use it.
    return ValidationResult(token.isArray() ? asArray(entry.validator) : entry.validator);
}

base::RespOrError<ValidationResult> Schema::Validator::validate(const DotPath& name, const STypeToken& token) const
{
    auto sType = m_schema.getType(name);
    // If same schema type return success with no runtime validator
    if (sType == token.type())
    {
        return ValidationResult();
    }

    // If the schema type is compatible with the token type, use the compatible validator if it exists
    const auto& entry = m_compatibles.at(sType);

    const auto& compatible = entry.compatibles.find(token.type());
    if (compatible != entry.compatibles.end())
    {
        if (compatible->second)
        {
            return ValidationResult(token.isArray() ? asArray(entry.validator) : entry.validator);
        }

        return ValidationResult();
    }

    return base::Error {
        fmt::format("Operation expects schema type '{}', but field '{}' is of incompatible schema type '{}'",
                    typeToStr(token.type()),
                    name,
                    typeToStr(sType))};
}

base::RespOrError<ValidationResult> Schema::Validator::validate(const DotPath& name, const ValueToken& token) const
{
    const auto& entry = m_compatibles.at(m_schema.getType(name));

    // When validating json values, if the schema type has a validator, validate the value
    if (entry.validator)
    {
        auto validator = token.isArray() ? asArray(entry.validator) : entry.validator;
        auto res = validator(token.value());

        if (base::isError(res))
        {
            return base::Error {fmt::format("Field '{}' value validation failed: {}", name, res.value().message)};
        }
    }

    // If the value is valid, return success with no runtime validator
    return ValidationResult();
}

base::RespOrError<ValidationResult> Schema::Validator::validate(const DotPath& name, const ValidationToken& token) const
{

    // If not a schema field, allways return success with no runtime validator
    if (!m_schema.hasField(name))
    {
        return ValidationResult();
    }

    // If no token, runtime validation only
    if (!token)
    {
        auto sType = m_schema.getType(name);
        const auto& entry = m_compatibles.at(sType);
        auto validator = m_schema.isArray(name) ? asArray(entry.validator) : entry.validator;
        return ValidationResult(validator);
    }

    // If array missmatch, return error
    if (m_schema.isArray(name) != token->isArray())
    {
        return base::Error {fmt::format("Operation expects {}, but field '{}' is{}",
                                        token->isArray() ? "an array" : "a non-array",
                                        name,
                                        m_schema.isArray(name) ? "" : " not")};
    }

    // Call the appropriate validation function based on the token type
    if (token->isJType())
    {
        return validate(name, *std::static_pointer_cast<JTypeToken>(token));
    }
    if (token->isSType())
    {
        return validate(name, *std::static_pointer_cast<STypeToken>(token));
    }
    if (token->isValue())
    {
        return validate(name, *std::static_pointer_cast<ValueToken>(token));
    }

    // Base token do not perform build validation aside from array missmatch, return success with runtime validator
    auto sType = m_schema.getType(name);
    const auto& entry = m_compatibles.at(sType);
    auto validator = m_schema.isArray(name) ? asArray(entry.validator) : entry.validator;
    return ValidationResult(validator);
}
} // namespace schemf
