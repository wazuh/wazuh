#include "builders/opmap/map.hpp"

namespace builder::builders::opmap
{

namespace
{
MapOp mapValue(const Value& value, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto jValue(value.value());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    return
        [successTrace, runState = buildCtx->runState(), jValue = std::move(jValue)](base::ConstEvent event) -> MapResult
    {
        RETURN_SUCCESS(runState, json::Json(jValue), successTrace);
    };
}

MapOp mapReference(const Reference& reference, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto referenceNotFound =
        fmt::format("{} -> Reference '{}' not found", buildCtx->context().opName, reference.dotPath());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    return [successTrace, runState = buildCtx->runState(), referenceNotFound, referencePath = reference.jsonPath()](
               base::ConstEvent event) -> MapResult
    {
        if (!event->exists(referencePath))
        {
            RETURN_FAILURE(runState, json::Json(), referenceNotFound);
        }

        auto jValue = event->getJson(referencePath).value();

        RETURN_SUCCESS(runState, jValue, successTrace);
    };
}
} // namespace

MapOp mapBuilder(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        return mapValue(*std::static_pointer_cast<Value>(opArgs[0]), buildCtx);
    }
    return mapReference(*std::static_pointer_cast<Reference>(opArgs[0]), buildCtx);
}

DynamicValToken mapValidator()
{
    auto resolver = [](const std::vector<OpArg>& opArgs, const schemf::IValidator& validator) -> schemf::ValidationToken
    {
        utils::assertSize(opArgs, 1);

        if (opArgs[0]->isValue())
        {
            return schemf::ValueToken::create(std::static_pointer_cast<Value>(opArgs[0])->value());
        }

        return schemf::tokenFromReference(std::static_pointer_cast<Reference>(opArgs[0])->dotPath(), validator);
    };

    return resolver;
}
} // namespace builder::builders::opmap
