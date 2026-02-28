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

/**
 * @brief Internal validator implementation for Schema.
 *
 * Holds a map of compatible types and their validation rules, and provides
 * overloaded validate methods for different token types.
 */
class Schema::Validator
{
private:
    std::unordered_map<schemf::Type, ValidationInfo> m_compatibles;
    const Schema& m_schema;

    /** @brief Register all type compatibility rules. */
    void registerCompatibles();

    /**
     * @brief Validate a field against a JSON type token.
     *
     * @param name Dot-separated field path.
     * @param token The JSON type token.
     * @return base::RespOrError<ValidationResult> Validation result or error.
     */
    base::RespOrError<ValidationResult> validate(const DotPath& name, const JTypeToken& token) const;

    /**
     * @brief Validate a field against a schema type token.
     *
     * @param name Dot-separated field path.
     * @param token The schema type token.
     * @return base::RespOrError<ValidationResult> Validation result or error.
     */
    base::RespOrError<ValidationResult> validate(const DotPath& name, const STypeToken& token) const;

    /**
     * @brief Validate a field against a JSON value token.
     *
     * @param name Dot-separated field path.
     * @param token The value token.
     * @return base::RespOrError<ValidationResult> Validation result or error.
     */
    base::RespOrError<ValidationResult> validate(const DotPath& name, const ValueToken& token) const;

public:
    ~Validator() = default;
    Validator(const Schema& schema)
        : m_schema(schema)
    {
        registerCompatibles();
    }

    /**
     * @brief Validate a field against a validation token (dispatch to typed overloads).
     *
     * @param name Dot-separated field path.
     * @param token The validation token.
     * @return base::RespOrError<ValidationResult> Validation result or error.
     */
    base::RespOrError<ValidationResult> validate(const DotPath& name, const ValidationToken& token) const;
};
} // namespace schemf
