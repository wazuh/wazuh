#include "array.hpp"

namespace builder::builders::optransform
{
TransformBuilder getArrayAppendBuilder(bool unique, bool atleastOne)
{
    return [unique, atleastOne](const Reference& targetField,
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

        json::Json::Type targetFieldtype;
        auto isInSchema {buildCtx->validator().hasField(targetField.dotPath())};
        if (isInSchema)
        {
            targetFieldtype = typeToJType(buildCtx->validator().getType(targetField.dotPath()));
        }

        auto arrayValidator = base::getResponse<schemf::ValidationResult>(result).getValidator();

        // Transform the vector of arguments into a vector of map ops
        using AppendOp = std::function<base::OptError(std::vector<json::Json>&, json::Json::Type&, const base::Event&)>;
        std::vector<AppendOp> appendOps;
        appendOps.reserve(opArgs.size());
        for (auto i = 0; i < opArgs.size(); ++i)
        {
            if (opArgs[i]->isValue())
            {
                const auto& asValue = std::static_pointer_cast<const Value>(opArgs[i]);
                if (isInSchema)
                {
                    if (asValue->value().type() != targetFieldtype)
                    {
                        throw std::runtime_error(fmt::format("Expected '{}' value but got value of type '{}'",
                                                             json::Json::typeToStr(targetFieldtype),
                                                             json::Json::typeToStr(asValue->value().type())));
                    }
                }

                appendOps.emplace_back(
                    [targetField = targetField.jsonPath(),
                     i,
                     targetFieldtype,
                     unique,
                     isInSchema,
                     value = asValue->value()](std::vector<json::Json>& targetArray,
                                               json::Json::Type& valueType,
                                               const base::Event& event) -> base::OptError
                    {
                        if (json::Json::Type::Unknow == valueType)
                        {
                            if (!isInSchema)
                            {
                                // If the target field is empty, take as type the type of the first element to be added,
                                // otherwise take the type of the first element of the target field.
                                if (!event->getArray(targetField).has_value())
                                {
                                    valueType = value.type();
                                }
                                else
                                {
                                    valueType = event->getArray(targetField).value()[0].type();
                                }
                            }
                            else
                            {
                                valueType = targetFieldtype;
                            }
                        }

                        if (value.type() != valueType)
                        {
                            return base::Error {fmt::format("Expected '{}' value but got value of type '{}'",
                                                            json::Json::typeToStr(valueType),
                                                            json::Json::typeToStr(value.type()))};
                        }

                        if (unique)
                        {
                            if (std::find(targetArray.begin(), targetArray.end(), value) != targetArray.end())
                            {
                                return base::noError();
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

                appendOps.emplace_back(
                    [targetField = targetField.jsonPath(),
                     i,
                     targetFieldtype,
                     isInSchema,
                     refNotFound,
                     unique,
                     atleastOne,
                     referencePath = std::static_pointer_cast<const Reference>(opArgs[i])->jsonPath()](
                        std::vector<json::Json>& targetArray,
                        json::Json::Type& valueType,
                        const base::Event& event) -> base::OptError
                    {
                        auto value = event->getJson(referencePath);
                        if (!value)
                        {
                            if (atleastOne)
                            {
                                return base::noError();
                            }
                            return base::Error {refNotFound};
                        }

                        if (json::Json::Type::Unknow == valueType)
                        {
                            if (!isInSchema)
                            {
                                // If the target field is empty, take as type the type of the first element to be added,
                                // otherwise take the type of the first element of the target field.
                                if (!event->getArray(targetField).has_value())
                                {
                                    valueType = value.value().type();
                                }
                                else
                                {
                                    valueType = event->getArray(targetField).value()[0].type();
                                }
                            }
                            else
                            {
                                valueType = targetFieldtype;
                            }
                        }

                        if (value->type() != valueType)
                        {
                            return base::Error {fmt::format("Expected '{}' reference but got reference of type '{}'",
                                                            json::Json::typeToStr(valueType),
                                                            json::Json::typeToStr(value->type()))};
                        }

                        if (unique)
                        {
                            if (std::find(targetArray.begin(), targetArray.end(), value.value()) != targetArray.end())
                            {
                                return base::noError();
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

        const auto referencesNotFound =
            fmt::format("{} -> Failure: None of the references were found or all the elements already existed",
                        buildCtx->context().opName);

        // TransformOp
        return [successTrace,
                runState = buildCtx->runState(),
                targetField = targetField.jsonPath(),
                arrayValidator,
                failureTrace,
                failureNotArray,
                referencesNotFound,
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

            auto valueType = json::Json::Type::Unknow;
            auto initialSize = targetArray.size();
            for (auto i = 0; i < appendOps.size(); i++)
            {
                auto res = appendOps[i](targetArray, valueType, event);
                if (base::isError(res))
                {
                    RETURN_FAILURE(runState, event, failureTrace + base::getError(res).message);
                }
            }

            if (targetArray.size() == initialSize)
            {
                RETURN_FAILURE(runState, event, referencesNotFound);
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
