// TODO: Deprecated, remove once all tests are updated

#ifndef _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
#define _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP

#include <memory>
#include <stdexcept>

#include <schemf/ivalidator.hpp>

namespace schemf::mocks
{

class EmptySchema : public schemf::IValidator
{
public:
    EmptySchema() = default;
    ~EmptySchema() = default;

    Type getType(const DotPath& name) const override { throw std::runtime_error("Not implemented"); }

    bool hasField(const DotPath& name) const override { return false; }

    json::Json::Type getJsonType(const DotPath& name) const override { throw std::runtime_error("Not implemented"); }

    base::RespOrError<TargetFieldKind> validateTargetField(const DotPath& name) const override
    {
        if (name.isRoot())
        {
            return TargetFieldKind::SCHEMA;
        }

        const auto& root = name.parts().front();
        if (!root.empty() && root.front() == '_')
        {
            return TargetFieldKind::TEMPORARY;
        }

        return base::Error {
            "Field is not defined in WCS schema and is not a temporary field (root must start with '_')"};
    }

    base::RespOrError<ValidationResult> validate(const DotPath& name, const ValidationToken&) const override
    {
        auto res = validateTargetField(name);
        if (base::isError(res))
        {
            return base::getError(res);
        }

        return ValidationResult();
    }

    base::RespOrError<ValidationResult> validate(const DotPath& name, const json::Json&) const override
    {
        auto res = validateTargetField(name);
        if (base::isError(res))
        {
            return base::getError(res);
        }

        return ValidationResult();
    }

    // TODO DELETE THIS
    static std::shared_ptr<EmptySchema> create() { return std::make_shared<EmptySchema>(); }
};

} // namespace schemf::mocks

#endif // _SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
