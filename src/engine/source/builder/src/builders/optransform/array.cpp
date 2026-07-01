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

        // Allowed fields
        auto assetType = base::Name(buildCtx->context().assetName).parts().front();
        if (!buildCtx->allowedFields().check(assetType, targetField.dotPath()))
        {
            throw std::runtime_error(
                fmt::format("Field '{}' is not allowed in '{}'", targetField.dotPath(), assetType));
        }

        // Validation
        auto result = buildCtx->validator().validate(targetField.dotPath(), schemf::elementValidationToken());
        if (base::isError(result))
        {
            throw std::runtime_error(base::getError(result).message);
        }

        json::Json::Type targetFieldtype {json::Json::Type::Unknown};
        auto isInSchema {buildCtx->validator().hasField(targetField.dotPath())};
        if (isInSchema)
        {
            targetFieldtype = typeToJType(buildCtx->validator().getType(targetField.dotPath()));
        }

        auto valueValidator = base::getResponse<schemf::ValidationResult>(result).getValidator();

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
                    if (asValue->type() != targetFieldtype)
                    {
                        throw std::runtime_error(fmt::format("Expected '{}' value but got value of type '{}'",
                                                             json::Json::typeToStr(targetFieldtype),
                                                             json::Json::typeToStr(asValue->type())));
                    }
                }

                if (asValue->isStringValue())
                {
                    // For string Values, capture string directly to avoid permanent json::Json allocation
                    appendOps.emplace_back(
                        [targetFieldtype, unique, isInSchema, strValue = std::string(asValue->getStringDirect())](
                            std::vector<json::Json>& targetArray,
                            json::Json::Type& valueType,
                            const base::Event&) -> base::OptError
                        {
                            if (json::Json::Type::Unknown == valueType)
                            {
                                if (isInSchema)
                                {
                                    valueType = targetFieldtype;
                                }
                                else if (!targetArray.empty())
                                {
                                    valueType = targetArray.front().type();
                                }
                                else
                                {
                                    valueType = json::Json::Type::String;
                                }
                            }

                            if (json::Json::Type::String != valueType)
                            {
                                return base::Error {fmt::format("Expected '{}' value but got value of type '{}'",
                                                                json::Json::typeToStr(valueType),
                                                                json::Json::typeToStr(json::Json::Type::String))};
                            }

                            json::Json jValue;
                            jValue.setString(strValue);

                            if (unique)
                            {
                                if (std::find(targetArray.begin(), targetArray.end(), jValue) != targetArray.end())
                                {
                                    return base::noError();
                                }
                            }

                            targetArray.emplace_back(std::move(jValue));
                            return base::noError();
                        });
                }
                else
                {
                    appendOps.emplace_back(
                        [targetFieldtype, unique, isInSchema, value = asValue->sharedValue()](
                            std::vector<json::Json>& targetArray,
                            json::Json::Type& valueType,
                            const base::Event&) -> base::OptError
                        {
                            if (json::Json::Type::Unknown == valueType)
                            {
                                if (isInSchema)
                                {
                                    valueType = targetFieldtype;
                                }
                                else if (!targetArray.empty())
                                {
                                    valueType = targetArray.front().type();
                                }
                                else
                                {
                                    valueType = value->type();
                                }
                            }

                            if (value->type() != valueType)
                            {
                                return base::Error {fmt::format("Expected '{}' value but got value of type '{}'",
                                                                json::Json::typeToStr(valueType),
                                                                json::Json::typeToStr(value->type()))};
                            }

                            if (unique)
                            {
                                if (std::find(targetArray.begin(), targetArray.end(), *value) != targetArray.end())
                                {
                                    return base::noError();
                                }
                            }

                            targetArray.emplace_back(*value);
                            return base::noError();
                        });
                }
            }
            else
            {
                const auto refNotFound =
                    fmt::format("'{}' not found", std::static_pointer_cast<const Reference>(opArgs[i])->dotPath());

                appendOps.emplace_back(
                    [targetFieldtype,
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

                        if (json::Json::Type::Unknown == valueType)
                        {
                            if (isInSchema)
                            {
                                valueType = targetFieldtype;
                            }
                            else if (!targetArray.empty())
                            {
                                valueType = targetArray.front().type();
                            }
                            else
                            {
                                valueType = value->type();
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

                        targetArray.emplace_back(std::move(value.value()));
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
                isTestMode = buildCtx->isTestMode(),
                targetField = targetField.jsonPath(),
                valueValidator,
                failureTrace,
                failureNotArray,
                referencesNotFound,
                appendOps = std::move(appendOps)](base::Event event) -> TransformResult
        {
            if (event->exists(targetField) && !event->isArray(targetField))
            {
                RETURN_FAILURE(isTestMode, event, failureNotArray);
            }

            auto targetArray = event->getArray(targetField).value_or(std::vector<json::Json> {});

            auto valueType = json::Json::Type::Unknown;
            auto initialSize = targetArray.size();
            for (auto i = 0; i < appendOps.size(); i++)
            {
                auto res = appendOps[i](targetArray, valueType, event);
                if (base::isError(res))
                {
                    RETURN_FAILURE(isTestMode, event, failureTrace + base::getError(res).message);
                }
            }

            if (targetArray.size() == initialSize)
            {
                RETURN_FAILURE(isTestMode, event, referencesNotFound);
            }

            auto jArray = json::Json();
            jArray.setArray();

            for (const auto& item : targetArray)
            {
                jArray.appendJson(item);
            }

            if (valueValidator != nullptr)
            {
                auto res = valueValidator(jArray);
                if (base::isError(res))
                {
                    RETURN_FAILURE(isTestMode, event, failureTrace + base::getError(res).message);
                }
            }

            event->set(targetField, jArray);

            RETURN_SUCCESS(isTestMode, event, successTrace);
        };
    };
}
} // namespace builder::builders::optransform
