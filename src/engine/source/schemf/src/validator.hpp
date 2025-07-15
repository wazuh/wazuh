#include "schema.hpp"

#include <unordered_map>

namespace schemf
{
/**
 * @brief Validation information for a specific schema type.
 *
 */
struct ValidationInfo
{
    json::Json::Type type;    ///< Associated JSON type.
    ValueValidator validator; ///< Validator for the json value.
    /// Compatible types. The bool value indicates whether the compatible type needs additional validation.
    std::unordered_map<schemf::Type, bool> compatibles;
};

class Schema::Validator
{
private:
    std::unordered_map<schemf::Type, ValidationInfo> m_compatibles;
    const Schema& m_schema;

    void registerCompatibles();

    base::RespOrError<ValidationResult> validate(const DotPath& name, const JTypeToken& token) const;
    base::RespOrError<ValidationResult> validate(const DotPath& name, const STypeToken& token) const;
    base::RespOrError<ValidationResult> validate(const DotPath& name, const ValueToken& token) const;

public:
    ~Validator() = default;
    Validator(const Schema& schema)
        : m_schema(schema)
    {
        registerCompatibles();
    }

    base::RespOrError<ValidationResult> validate(const DotPath& name, const ValidationToken& token) const;
};
} // namespace schemf
