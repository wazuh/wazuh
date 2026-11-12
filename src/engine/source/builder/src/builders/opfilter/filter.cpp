// SPDX-License-Identifier: AGPL-3.0-or-later
#include "builders/opmap/map.hpp"

#include "builders/utils.hpp"

namespace builder::builders::opfilter
{

namespace
{
FilterOp filterValue(const Reference& targetField, const Value& value, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto targetNotFound =
        fmt::format("{} -> Target field '{}' not found", buildCtx->context().opName, targetField.dotPath());
    auto valueMissmatch =
        fmt::format("{} -> Value missmatch for reference '{}'", buildCtx->context().opName, targetField.dotPath());
    const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
    auto isTestMode = buildCtx->isTestMode();

    // For string-only Values, capture the string directly (avoids json::Json steady-state overhead)
    if (value.isStringValue())
    {
        std::string_view sv;
        value.getString(sv);
        auto strValue = std::string(sv);
        return [targetField = json::PointerPath(targetField.jsonPath()),
                targetNotFound,
                valueMissmatch,
                successTrace,
                isTestMode,
                strValue](base::ConstEvent event) -> FilterResult
        {
            // One lookup: it tells a missing field apart from a different (or non-string) value
            std::string_view got;
            const auto res = event->getString(got, targetField);
            if (res == json::RetGet::NotFound)
            {
                RETURN_FAILURE(isTestMode, false, targetNotFound);
            }

            if (res != json::RetGet::Success || got != strValue)
            {
                RETURN_FAILURE(isTestMode, false, valueMissmatch);
            }

            RETURN_SUCCESS(isTestMode, true, successTrace);
        };
    }

    auto jValue = value.sharedValue();
    return [targetField = json::PointerPath(targetField.jsonPath()),
            targetNotFound,
            valueMissmatch,
            successTrace,
            isTestMode,
            jValue](base::ConstEvent event) -> FilterResult
    {
        // equals() is false for a missing field too: only the test-mode trace needs to tell them apart
        if (!event->equals(targetField, *jValue))
        {
            RETURN_FAILURE(isTestMode, false, event->exists(targetField) ? valueMissmatch : targetNotFound);
        }

        RETURN_SUCCESS(isTestMode, true, successTrace);
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
    return [targetField = json::PointerPath(targetField.jsonPath()),
            successTrace,
            isTestMode = buildCtx->isTestMode(),
            referenceNotFound,
            targetNotFound,
            valueMissmatch,
            referencePath = json::PointerPath(reference.jsonPath())](base::ConstEvent event) -> FilterResult
    {
        // equals() is false when either field is missing: only the test-mode trace needs to know which
        if (!event->equals(targetField, referencePath))
        {
            RETURN_FAILURE(isTestMode,
                           false,
                           !event->exists(targetField)     ? targetNotFound
                           : !event->exists(referencePath) ? referenceNotFound
                                                           : valueMissmatch);
        }

        RETURN_SUCCESS(isTestMode, true, successTrace);
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
    auto resolver = [](const std::vector<OpArg>& opArgs, const schemf::IValidator& validator) -> schemf::ValidationToken
    {
        utils::assertSize(opArgs, 1);

        if (opArgs[0]->isValue())
        {
            return schemf::ValueToken::create(std::static_pointer_cast<Value>(opArgs[0])->value());
        }
        else
        {
            return schemf::tokenFromReference(std::static_pointer_cast<Reference>(opArgs[0])->dotPath(), validator);
        }
    };

    return resolver;
}
} // namespace builder::builders::opfilter
