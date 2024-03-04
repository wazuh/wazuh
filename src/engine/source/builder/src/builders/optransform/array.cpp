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
        auto result = buildCtx->validator().validate(targetField.dotPath(), schemf::isArrayToken());
        if (base::isError(result))
        {
            throw std::runtime_error(base::getError(result).message);
        }

        auto arrayValidator = base::getResponse<schemf::ValidationResult>(result).getValidator();

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
                        }

                        targetArray.emplace_back(value);

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
                        }

                        targetArray.emplace_back(value.value());
                        return base::noError();
                    });
            }
        }

        // Traces
        const auto successTrace = fmt::format("{} -> Success", buildCtx->context().opName);
        const auto failureTrace = fmt::format("{} -> Failure: ", buildCtx->context().opName);
        const auto failureNotArray =
            fmt::format("{} -> Target field '{}' is not an array", buildCtx->context().opName, targetField.dotPath());

        // TransformOp
        return [successTrace,
                runState = buildCtx->runState(),
                targetField = targetField.jsonPath(),
                arrayValidator,
                failureTrace,
                failureNotArray,
                appendOps = std::move(appendOps)](base::Event event) -> TransformResult
        {
            if (event->exists(targetField) && !event->isArray(targetField))
            {
                RETURN_FAILURE(runState, event, failureNotArray);
            }

            auto resp = event->getArray(targetField);
            std::vector<json::Json> targetArray = resp.value_or(std::vector<json::Json>());
            if (resp)
            {
                targetArray = std::vector<json::Json>(resp.value());
            }

            bool atleastOne = false;
            for (const auto& appendOp : appendOps)
            {
                auto res = appendOp(targetArray, event);
                if (!atleastOne && !base::isError(res))
                {
                    atleastOne = true;
                }
            }

            if (!atleastOne)
            {
                RETURN_FAILURE(runState, event, failureTrace + "No valid value to append");
            }

            auto jArray = json::Json();
            jArray.setArray();

            for (const auto& item : targetArray)
            {
                jArray.appendJson(item);
            }

            // Validate the array
            if (arrayValidator != nullptr)
            {
                auto res = arrayValidator(jArray);
                if (base::isError(res))
                {
                    RETURN_FAILURE(runState, event, failureTrace + base::getError(res).message);
                }
            }

            event->set(targetField, jArray);

            RETURN_SUCCESS(runState, event, successTrace);
        };
    };
}
} // namespace builder::builders::optransform
