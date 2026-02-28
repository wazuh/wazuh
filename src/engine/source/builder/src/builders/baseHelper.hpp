#ifndef _BUILDER_BUILDERS_BASEHELPER_HPP
#define _BUILDER_BUILDERS_BASEHELPER_HPP

#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Wrap an OpBuilder with schema type validation.
 *
 * @param builder The original OpBuilder.
 * @param targetField Target field reference.
 * @param validationToken Validation token for schema checking.
 * @param validator Schema validator.
 * @return OpBuilder The wrapped builder.
 */
OpBuilder buildType(const OpBuilder& builder,
                    const Reference& targetField,
                    const schemf::ValidationToken& validationToken,
                    const schemf::IValidator& validator);

/**
 * @brief Wrap an OpBuilder with runtime validation.
 *
 * @param builder The original OpBuilder.
 * @param targetField Target field reference.
 * @param validationResult Validation result containing runtime validator.
 * @return OpBuilder The wrapped builder.
 */
OpBuilder
runType(const OpBuilder& builder, const Reference& targetField, const schemf::ValidationResult& validationResult);

/**
 * @brief Convert a FilterBuilder to a TransformBuilder.
 *
 * @param builder The filter builder.
 * @return TransformBuilder The equivalent transform builder.
 */
TransformBuilder filterToTransform(const FilterBuilder& builder);

/**
 * @brief Convert a MapBuilder to a TransformBuilder for a target field.
 *
 * @param builder The map builder.
 * @param targetField Target field reference.
 * @return TransformBuilder The equivalent transform builder.
 */
TransformBuilder mapToTransform(const MapBuilder& builder, const Reference& targetField);

/**
 * @brief Convert any OpBuilder variant to a TransformBuilder.
 *
 * @param builder The operation builder.
 * @param targetField Target field reference.
 * @return TransformBuilder The resulting transform builder.
 */
TransformBuilder toTransform(const OpBuilder& builder, const Reference& targetField);

/**
 * @brief Wrap a TransformOp into a base::Expression term.
 *
 * @param op The transform operation.
 * @param name Name of the expression node.
 * @return base::Expression The expression wrapping the operation.
 */
base::Expression toExpression(const TransformOp& op, const std::string& name);

/**
 * @brief Helper type enumeration.
 */
enum class HelperType
{
    MAP,
    FILTER
};

/**
 * @brief Build a helper expression from a parsed helper name, target field, and arguments.
 *
 * @param helperName Name of the helper function.
 * @param targetField Target field reference.
 * @param opArgs Operation arguments.
 * @param buildCtx Build context.
 * @param helperType Type of helper (MAP or FILTER).
 * @return base::Expression The built expression.
 */
base::Expression baseHelperBuilder(const std::string& helperName,
                                   const Reference& targetField,
                                   std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   HelperType helperType);

/**
 * @brief Build a helper expression from a JSON definition string.
 *
 * @param definition JSON definition of the helper.
 * @param buildCtx Build context.
 * @param helperType Type of helper (MAP or FILTER).
 * @return base::Expression The built expression.
 */
base::Expression baseHelperBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   HelperType helperType);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_BASEHELPER_HPP
