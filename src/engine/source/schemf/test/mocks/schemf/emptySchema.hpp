#ifndef SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
#define SCHEMF_MOCKS_EMPTY_SCHEMA_HPP

#include <memory>
#include <optional>
#include <stdexcept>

#include <schemf/ivalidator.hpp>

namespace schemf::mocks
{

class EmptySchema : public schemf::IValidator
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

    // TODO DELETE THIS
    static std::shared_ptr<EmptySchema> create() { return std::make_shared<EmptySchema>(); }
};

} // namespace schemf::mocks

#endif // SCHEMF_MOCKS_EMPTY_SCHEMA_HPP
