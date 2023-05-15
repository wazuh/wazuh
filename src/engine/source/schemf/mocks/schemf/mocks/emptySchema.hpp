#ifndef _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
#define _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP

#include <memory>
#include <stdexcept>

#include <schemf/ischema.hpp>

namespace schemf::mocks
{

class EmptySchema : public schemf::ISchema
{
public:
    EmptySchema() = default;
    ~EmptySchema() = default;

    json::Json::Type getType(const DotPath& name) const override { throw std::runtime_error("Not implemented"); }

    bool hasField(const DotPath& name) const override { return false; }

    static std::shared_ptr<EmptySchema> create() { return std::make_shared<EmptySchema>(); }

    std::optional<base::Error> validate(const DotPath& target, const json::Json& value) const override
    {
        throw std::runtime_error("Not implemented");
    }

    std::optional<base::Error> validate(const DotPath& target, const DotPath& reference) const override
    {
        throw std::runtime_error("Not implemented");
    }

    ISchema::RuntimeValidator getRuntimeValidator(const DotPath& target) const override
    {
        throw std::runtime_error("Not implemented");
    }
};

} // namespace schemf::mocks

#endif // _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
