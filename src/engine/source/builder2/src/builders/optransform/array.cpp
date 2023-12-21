#include "array.hpp"

namespace builder::builders::optransform
{
TransformBuilder getArrayAppendBuilder(bool unique)
{
    return [unique](const Reference& targetField,
                    const std::vector<OpArg>& opArgs,
                    const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        // Check parameters
        utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);

        // Validation
        std::unordered_map<size_t, schemval::RuntimeValidator> runValidators;
        const auto& validator = buildCtx->validator();
        for (auto i = 0; i < opArgs.size(); ++i)
        {
            const auto& opArg = opArgs[i];
            schemval::ValidationToken validationToken;
            if (opArg->isValue())
            {
                const auto& value = std::static_pointer_cast<const Value>(opArg);
                validationToken = validator.createToken(value->value());
            }
            else
            {
                const auto& reference = std::static_pointer_cast<const Reference>(opArg);
                validationToken = validator.createToken(reference->dotPath());
            }

            auto res = validator.validateArray(targetField.dotPath(), validationToken);
            if (base::isError(res))
            {
                throw std::runtime_error(base::getError(res).message);
            }

            if (validationToken.needsRuntimeValidation())
            {
                // Validate items with the ignoreArray flag set to true
                auto runValidator = validator.getRuntimeValidator(targetField.dotPath(), true);
                if (!base::isError(runValidator))
                {
                    runValidators.emplace(i, base::getResponse<schemval::RuntimeValidator>(runValidator));
                }
                runValidators.emplace(i, nullptr);
            }
            else
            {
                runValidators.emplace(i, nullptr);
            }
        }

        // Transform the vector of arguments into a vector of map ops
        using AppendOp = std::function<base::OptError(std::vector<json::Json>&, const base::Event&)>;
        std::vector<AppendOp> appendOps;
        appendOps.reserve(opArgs.size());
        for (auto i = 0; i < opArgs.size(); ++i)
        {
            if (opArgs[i]->isValue())
            {
                const auto duplicatedValue = fmt::format(
                    "'{}' value is duplicated", std::static_pointer_cast<const Value>(opArgs[i])->value().str());

                appendOps.emplace_back(
                    [targetField = targetField.jsonPath(),
                     duplicatedValue,
                     unique,
                     value = std::static_pointer_cast<const Value>(opArgs[i])->value()](
                        std::vector<json::Json>& targetArray, const base::Event& event) -> base::OptError
                    {
                        if (unique)
                        {
                            if (std::find(targetArray.begin(), targetArray.end(), value) != targetArray.end())
                            {
                                return base::Error {duplicatedValue};
                            }

                            targetArray.emplace_back(value);
                        }

                        event->appendJson(value, targetField);
                        return base::noError();
                    });
            }
            else
            {
                const auto refNotFound =
                    fmt::format("'{}' not found", std::static_pointer_cast<const Reference>(opArgs[i])->dotPath());
                const auto refValueNotValid = fmt::format(
                    "'{}' value is not valid", std::static_pointer_cast<const Reference>(opArgs[i])->dotPath());
                const auto duplicatedValue =
                    fmt::format("'{}' reference's value is duplicated",
                                std::static_pointer_cast<const Reference>(opArgs[i])->dotPath());

                appendOps.emplace_back(
                    [targetField = targetField.jsonPath(),
                     refNotFound,
                     refValueNotValid,
                     duplicatedValue,
                     unique,
                     runValidator = runValidators[i],
                     referencePath = std::static_pointer_cast<const Reference>(opArgs[i])->jsonPath()](
                        std::vector<json::Json>& targetArray, const base::Event& event) -> base::OptError
                    {
                        auto value = event->getJson(referencePath);
                        if (!value)
                        {
                            return base::Error {refNotFound};
                        }

                        if (unique)
                        {
                            if (std::find(targetArray.begin(), targetArray.end(), value.value()) != targetArray.end())
                            {
                                return base::Error {duplicatedValue};
                            }

                            targetArray.emplace_back(value.value());
                        }

                        if (runValidator && !runValidator(value.value()))
                        {
                            return base::Error {refValueNotValid};
                        }

                        event->appendJson(value.value(), targetField);
                        return base::noError();
                    });
            }
        }

        // Traces
        const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);

        // TransformOp
        return [successTrace,
                runState = buildCtx->runState(),
                targetField = targetField.jsonPath(),
                appendOps = std::move(appendOps)](base::Event event) -> TransformResult
        {
            std::vector<json::Json> targetArray;

            auto resp = event->getArray(targetField);
            if (resp)
            {
                targetArray = std::vector<json::Json>(resp.value());
            }

            for (const auto& appendOp : appendOps)
            {
                auto res = appendOp(targetArray, event);
            }

            RETURN_SUCCESS(runState, event, successTrace);
        };
    };
}
} // namespace builder::builders::optransform
