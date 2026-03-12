#ifndef SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
#define SCHEMF_MOCKS_EMPTY_SCHEMA_HPP

#include <memory>
#include <optional>
#include <stdexcept>

#include <schemf/ischema.hpp>

namespace schemf::mocks
{

// Simple schema mock to be used in tests to control field existence and validation.
class EmptySchema : public schemf::ISchema
{
public:
    EmptySchema() = default;
    ~EmptySchema() = default;

    // Configure whether validate() should succeed (true) or fail (false)
    bool m_validationResult {true};

    // Configure what hasField() should return
    bool m_hasFieldResult {false};

    json::Json::Type m_jsonTypeResult {json::Json::Type::Object};

    explicit EmptySchema(bool validationResult, bool hasFieldResult, json::Json::Type jsonTypeResult = json::Json::Type::Object)
        : m_validationResult(validationResult)
        , m_hasFieldResult(hasFieldResult)
        , m_jsonTypeResult(jsonTypeResult)
    {
    }

    Type getType(const DotPath&) const override { throw std::runtime_error("Not implemented"); }

    bool hasField(const DotPath&) const override { return m_hasFieldResult; }

    json::Json::Type getJsonType(const DotPath&) const override { return m_jsonTypeResult; }

    static std::shared_ptr<EmptySchema> create(bool validationResult = true, bool hasFieldResult = false, json::Json::Type jsonTypeResult = json::Json::Type::Object)
    {
        return std::make_shared<EmptySchema>(validationResult, hasFieldResult, jsonTypeResult);
    }
};

} // namespace schemf::mocks

#endif // SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
