#ifndef _BUILDER_BUILDERS_BASEHELPER_HPP
#define _BUILDER_BUILDERS_BASEHELPER_HPP

#include "builders/types.hpp"

namespace builder::builders
{

OpBuilder buildType(const OpBuilder& builder,
                    const Reference& targetField,
                    const schemf::ValidationToken& validationToken,
                    const schemf::IValidator& validator);

OpBuilder
runType(const OpBuilder& builder, const Reference& targetField, const schemf::ValidationResult& validationResult);

TransformBuilder filterToTransform(const FilterBuilder& builder);
TransformBuilder mapToTransform(const MapBuilder& builder, const Reference& targetField);
TransformBuilder toTransform(const OpBuilder& builder, const Reference& targetField);

base::Expression toExpression(const TransformOp& op, const std::string& name);

enum class HelperType
{
    MAP,
    FILTER
};

base::Expression baseHelperBuilder(const std::string& helperName,
                                   const Reference& targetField,
                                   std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   HelperType helperType);

base::Expression baseHelperBuilder(const json::Json& definition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   HelperType helperType);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_BASEHELPER_HPP
