#include "exists.hpp"

namespace
{
using namespace builder::builders;

FilterOp exists(const Reference& targetField,
                const std::vector<OpArg>& opArgs,
                const std::shared_ptr<const IBuildCtx>& buildCtx,
                bool negate)
{
    utils::assertSize(opArgs, 0);

    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    const auto failureTrace = fmt::format("{} -> Failure", buildCtx->context().opName);
    return [targetField = targetField.jsonPath(), runState = buildCtx->runState(), successTrace, failureTrace, negate](
               base::ConstEvent event) -> FilterResult
    {
        if (event->exists(targetField) == negate)
        {
            RETURN_FAILURE(runState, false, failureTrace);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}
} // namespace

namespace builder::builders::opfilter
{

FilterOp existsBuilder(const Reference& targetField,
                       const std::vector<OpArg>& opArgs,
                       const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return exists(targetField, opArgs, buildCtx, false);
}

FilterOp notExistsBuilder(const Reference& targetField,
                          const std::vector<OpArg>& opArgs,
                          const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return exists(targetField, opArgs, buildCtx, true);
}

} // namespace builder::builders::opfilter
