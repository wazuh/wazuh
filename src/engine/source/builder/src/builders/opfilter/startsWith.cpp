#include "startsWith.hpp"

#include <fmt/format.h>

#include <base/utils/stringUtils.hpp>

namespace
{
using namespace builder::builders;

FilterOp
startsWithValue(const Reference& targetField, const Value& value, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Value must be a string
    if (!value.value().isString())
    {
        throw std::runtime_error(fmt::format("Expected 'string' value but got '{}'", value.value().typeName()));
    }

    const auto targetNotFound =
        fmt::format("{} -> Target field '{}' not found", buildCtx->context().opName, targetField.dotPath());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    const auto failure = fmt::format("{} -> Failure", buildCtx->context().opName);
    const auto targetNotString =
        fmt::format("{} -> Target field '{}' is not a string", buildCtx->context().opName, targetField.dotPath());
    return [targetField = targetField.jsonPath(),
            value = json::Json(value.value()),
            runState = buildCtx->runState(),
            targetNotFound,
            failure,
            successTrace,
            targetNotString](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, targetNotFound);
        }

        auto targetValue = event->getJson(targetField).value();
        if (!targetValue.isString())
        {
            RETURN_FAILURE(runState, false, targetNotString);
        }

        auto targetString = targetValue.getString().value();
        auto valueString = value.getString().value();

        if (!base::utils::string::startsWith(targetString, valueString))
        {
            RETURN_FAILURE(runState, false, failure);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}

FilterOp startsWithReference(const Reference& targetField,
                             const Reference& reference,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    const auto& validator = buildCtx->validator();
    if (validator.hasField(reference.dotPath()) && validator.getType(reference.dotPath()) != schemf::Type::KEYWORD
        && validator.getType(reference.dotPath()) != schemf::Type::TEXT)
    {
        throw std::runtime_error(fmt::format("Reference '{}' is of type '{}' but expected 'keyword' or 'text'",
                                             reference.dotPath(),
                                             schemf::typeToStr(validator.getType(reference.dotPath()))));
    }

    const auto referenceNotFound =
        fmt::format("{} -> Reference '{}' not found", buildCtx->context().opName, reference.dotPath());
    const auto referenceNotString =
        fmt::format("{} -> Reference '{}' is not a string", buildCtx->context().opName, reference.dotPath());
    const auto targetNotFound =
        fmt::format("{} -> Target field '{}' not found", buildCtx->context().opName, targetField.dotPath());
    const auto targetNotString =
        fmt::format("{} -> Target field '{}' is not a string", buildCtx->context().opName, targetField.dotPath());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    const auto failure = fmt::format("{} -> Failure", buildCtx->context().opName);

    return [targetField = targetField.jsonPath(),
            reference = reference.jsonPath(),
            runState = buildCtx->runState(),
            referenceNotFound,
            referenceNotString,
            targetNotFound,
            targetNotString,
            successTrace,
            failure](base::ConstEvent event) -> FilterResult
    {
        if (!event->exists(targetField))
        {
            RETURN_FAILURE(runState, false, targetNotFound);
        }
        if (!event->exists(reference))
        {
            RETURN_FAILURE(runState, false, referenceNotFound);
        }

        auto targetValue = event->getJson(targetField).value();
        if (!targetValue.isString())
        {
            RETURN_FAILURE(runState, false, targetNotString);
        }

        auto referenceValue = event->getJson(reference).value();
        if (!referenceValue.isString())
        {
            RETURN_FAILURE(runState, false, referenceNotString);
        }

        auto targetString = targetValue.getString().value();
        auto referenceString = referenceValue.getString().value();
        if (!base::utils::string::startsWith(targetString, referenceString))
        {
            RETURN_FAILURE(runState, false, failure);
        }

        RETURN_SUCCESS(runState, true, successTrace);
    };
}
} // namespace

namespace builder::builders::opfilter
{

FilterOp startsWithBuilder(const Reference& targetField,
                           const std::vector<OpArg>& opArgs,
                           const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    utils::assertSize(opArgs, 1);

    if (opArgs[0]->isValue())
    {
        return startsWithValue(targetField, *std::static_pointer_cast<Value>(opArgs[0]), buildCtx);
    }
    else
    {
        return startsWithReference(targetField, *std::static_pointer_cast<Reference>(opArgs[0]), buildCtx);
    }
}

} // namespace builder::builders::opfilter
