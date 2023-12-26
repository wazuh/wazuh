#include "builders/opmap/map.hpp"

#include "builders/utils.hpp"

namespace builder::builders::opfilter
{

namespace
{
FilterOp filterValue(const Reference& targetField, const Value& value, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto jValue(value.value());

    auto targetNotFound =
        fmt::format("{} -> Target field '{}' not found", buildCtx->context().opName, targetField.dotPath());
    auto valueMissmatch =
        fmt::format("{} -> Value missmatch for reference '{}'", buildCtx->context().opName, targetField.dotPath());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    return [targetField = targetField.jsonPath(),
            targetNotFound,
            valueMissmatch,
            successTrace,
            runState = buildCtx->runState(),
            jValue = std::move(jValue)](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, targetNotFound);
        }

        if (!event->equals(targetField, jValue))
        {
            RETURN_FAILURE(runState, false, valueMissmatch);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}

FilterOp filterReference(const Reference& targetField,
                         const Reference& reference,
                         const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto referenceNotFound =
        fmt::format("{} -> Reference '{}' not found", buildCtx->context().opName, reference.dotPath());
    auto targetNotFound =
        fmt::format("{} -> Target field '{}' not found", buildCtx->context().opName, targetField.dotPath());
    auto valueMissmatch = fmt::format("{} -> Value missmatch for reference '{}' and target field '{}'",
                                      buildCtx->context().opName,
                                      reference.dotPath(),
                                      targetField.dotPath());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    return [targetField = targetField.jsonPath(),
            successTrace,
            runState = buildCtx->runState(),
            referenceNotFound,
            targetNotFound,
            valueMissmatch,
            referencePath = reference.jsonPath()](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, targetNotFound);
        }

        if (!event->exists(referencePath))
        {
            RETURN_FAILURE(runState, false, referenceNotFound);
        }

        if (!event->equals(targetField, referencePath))
        {
            RETURN_FAILURE(runState, false, valueMissmatch);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}
} // namespace

FilterOp filterBuilder(const Reference& targetField,
                       const std::vector<OpArg>& opArgs,
                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        return filterValue(targetField, *std::static_pointer_cast<Value>(opArgs[0]), buildCtx);
    }
    else
    {
        return filterReference(targetField, *std::static_pointer_cast<Reference>(opArgs[0]), buildCtx);
    }
}

DynamicValToken filterValidator()
{
    auto resolver = [](const std::vector<OpArg>& opArgs,
                       const schemval::IValidator& validator) -> schemval::ValidationToken
    {
        utils::assertSize(opArgs, 1);

        if (opArgs[0]->isValue())
        {
            return schemval::ValidationToken(std::static_pointer_cast<Value>(opArgs[0])->value());
        }
        else
        {
            return validator.createToken(std::static_pointer_cast<Reference>(opArgs[0])->dotPath());
        }
    };

    return resolver;
}
} // namespace builder::builders::opfilter
