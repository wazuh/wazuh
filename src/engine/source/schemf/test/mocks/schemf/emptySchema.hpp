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

    explicit EmptySchema(bool validationResult, bool hasFieldResult)
        : m_validationResult(validationResult)
        , m_hasFieldResult(hasFieldResult)
    {
    }

    Type getType(const DotPath&) const override { throw std::runtime_error("Not implemented"); }

    bool hasField(const DotPath&) const override { return m_hasFieldResult; }

    json::Json::Type getJsonType(const DotPath&) const override
    {
        if (m_validationResult)
        {
            return json::Json::Type::Object;
        }

        throw std::runtime_error("Not implemented");
    }

    static std::shared_ptr<EmptySchema> create(bool validationResult = true, bool hasFieldResult = false)
    {
        return std::make_shared<EmptySchema>(validationResult, hasFieldResult);
    }
};

} // namespace schemf::mocks

#endif // SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
