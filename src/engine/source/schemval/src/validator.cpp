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

base::OptError Validator::validate(const DotPath& destPath, const json::Json::Type& type) const
{
    if (m_schema->hasField(destPath))
    {
        auto sType = m_schema->getType(destPath);
        if (!isCompatible(sType, type))
        {
            return base::Error {fmt::format("Field '{}' is of type '{}', but the given value is of type '{}'",
                                            destPath,
                                            schemf::typeToStr(sType),
                                            json::Json::typeToStr(type))};
        }
    }
    return base::noError();
}

base::OptError Validator::validate(const DotPath& destPath, const DotPath& sourcePath) const
{
    if (m_schema->hasField(destPath) && m_schema->hasField(sourcePath))
    {
        auto sType = m_schema->getType(destPath);
        auto jType = getEntry(m_schema->getType(sourcePath)).jsonType;
        if (!isCompatible(sType, jType))
        {
            return base::Error {fmt::format("Field '{}' is of type '{}', but field '{}' is of type '{}'",
                                            destPath,
                                            schemf::typeToStr(sType),
                                            sourcePath,
                                            json::Json::typeToStr(jType))};
        }
    }
    return base::noError();
}

base::RespOrError<RuntimeValidator> Validator::getRuntimeValidator(const DotPath& destPath) const
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

    return validator;
}

} // namespace schemval
