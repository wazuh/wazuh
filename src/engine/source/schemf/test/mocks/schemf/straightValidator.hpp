// TODO: Deprecated, remove once all tests are updated

#ifndef _SCHEMF_MOCKS_SINGLE_FIELD_HPP
#define _SCHEMF_MOCKS_SINGLE_FIELD_HPP

#include <memory>
#include <stdexcept>

#include <schemf/ischema.hpp>

namespace schemf::mocks
{
class StraightValidator : public schemf::ISchema
{
public:
    StraightValidator() = default;
    ~StraightValidator() = default;

    bool validation;
    bool field;

    explicit StraightValidator(bool validation, bool field)
        : validation(validation)
        , field(field)
    {
    }

    json::Json::Type getType(const DotPath& name) const override { throw std::runtime_error("Not implemented"); }

    bool hasField(const DotPath& name) const override { return field; }

    static std::shared_ptr<StraightValidator> create(bool validation, bool field)
    {
        return std::make_shared<StraightValidator>(validation, field);
    }

    std::optional<base::Error> validate(const DotPath& target, const json::Json& value) const override
    {
        return validation ? std::nullopt : std::make_optional(base::Error {"Error"});
    }

    std::optional<base::Error> validate(const DotPath& target, const DotPath& reference) const override
    {
        return validation ? std::nullopt : std::make_optional(base::Error {"Error"});
    }

    RuntimeValidator getRuntimeValidator(const DotPath& target) const override
    {
        return [validation = validation](const json::Json& value) -> std::optional<base::Error>
        {
            return validation ? std::nullopt : std::make_optional(base::Error {"Error"});
        };
    }
};
} // namespace schemf::mocks

#endif // _SCHEMF_MOCKS_SINGLE_FIELD_HPP
