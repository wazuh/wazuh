// TODO: Deprecated, remove once all tests are updated

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

    Type getType(const DotPath& name) const override { throw std::runtime_error("Not implemented"); }

    bool isArray(const DotPath& name) const override { return false; }

    bool hasField(const DotPath& name) const override { return false; }

    json::Json::Type getJsonType(const DotPath& name) const override { throw std::runtime_error("Not implemented"); }

    // TODO DELETE THIS
    static std::shared_ptr<EmptySchema> create() { return std::make_shared<EmptySchema>(); }

};

} // namespace schemf::mocks

#endif // _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
