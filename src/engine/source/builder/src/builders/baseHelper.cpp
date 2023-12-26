#include "baseHelper.hpp"

#include <base/utils/stringUtils.hpp>
#include <fmt/format.h>

#include "builders/types.hpp"
#include "helperParser.hpp"

namespace
{
/**
 * @brief Set the Object if it does not exist
 *
 * @param targetField
 * @return base::Expression
 */
auto setObjectTerm(const std::string& field) -> base::Expression
{
    auto name {fmt::format("map.value[{}={}]", field, "{}")};
    auto successTrace {fmt::format("[{}] -> Success", name)};

    auto fn = [field, successTrace](const auto& e)
    {
        if (!e->isObject(field))
        {
            e->setObject(field);
        }
        return base::result::makeSuccess(std::move(e), successTrace);
    };
    return base::Term<base::EngineOp>::create("setObjectOp", fn);
}

/**
 * @brief Delete the Object if it is empty
 *
 * @param targetField
 * @return base::Expression
 */
auto deleteEmptyObjectTerm(const std::string& field) -> base::Expression
{
    auto name {fmt::format("unmap.ifEmpty.value[{}]", field)};
    auto successTrace {fmt::format("[{}] -> Success", name)};

    auto fn = [field, successTrace](const auto& e)
    {
        if (e->isObject(field) && e->isEmpty(field))
        {
            e->erase(field);
        }
        return base::result::makeSuccess(std::move(e), successTrace);
    };
    return base::Term<base::EngineOp>::create("deleteEmptyObject", fn);
}
} // namespace
namespace builder::builders
{

OpBuilder buildType(const OpBuilder& builder,
                    const Reference& targetField,
                    const schemval::ValidationToken& validationToken,
                    const schemval::IValidator& validator)
{
    auto res = validator.validate(targetField.dotPath(), validationToken);
    if (base::isError(res))
    {
        throw std::runtime_error(base::getError(res).message);
    }

    return builder;
}

OpBuilder runType(const OpBuilder& builder,
                  const Reference& targetField,
                  const schemval::ValidationToken& validationToken,
                  const schemval::IValidator& validator)
{
    if (!std::holds_alternative<MapBuilder>(builder) || !validationToken.needsRuntimeValidation())
    {
        return builder;
    }

    // Get runtime validator for target field if has any
    auto runValidator = validator.getRuntimeValidator(targetField.dotPath());
    if (base::isError(runValidator))
    {
        return builder;
    }

    // Wrapper Builder
    return [builder = std::get<MapBuilder>(builder),
            runValidator = base::getResponse<schemval::RuntimeValidator>(runValidator)](
               const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx) -> MapOp
    {
        auto mapOp = builder(opArgs, buildCtx);

        // Wrapper MapOp
        const auto& invalidTrace = fmt::format("{} -> failed type validation", buildCtx->context().opName);
        return [invalidTrace, mapOp, runValidator, runState = buildCtx->runState()](base::ConstEvent event) -> MapResult
        {
            auto mapRes = mapOp(event);
            if (mapRes.failure())
            {
                return std::move(mapRes);
            }

            const auto& value = mapRes.payload();

            auto valid = runValidator(value);
            if (!valid)
            {
                RETURN_FAILURE(runState, json::Json(), invalidTrace);
            }

            return std::move(mapRes);
        };
    };
}

TransformBuilder filterToTransform(const FilterBuilder& builder)
{
    return [builder](const Reference& targetField,
                     const std::vector<OpArg>& opArgs,
                     const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        auto filterOp = builder(targetField, opArgs, buildCtx);

        // Wrapper TransformOp
        return [filterOp](base::Event event) -> TransformResult
        {
            auto filterRes = filterOp(event);
            if (filterRes.failure())
            {
                return base::result::makeFailure<base::Event>(event, filterRes.popTrace());
            }

            return base::result::makeSuccess(std::move(event), filterRes.popTrace());
        };
    };
}

TransformBuilder mapToTransform(const MapBuilder& builder, const Reference& targetField)
{
    return [builder, targetField](const Reference&,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx) -> TransformOp
    {
        auto mapOp = builder(opArgs, buildCtx);

        // Wrapper TransformOp
        return [mapOp, targetField](base::Event event) -> TransformResult
        {
            auto mapRes = mapOp(event);
            if (mapRes.failure())
            {
                return base::result::makeFailure<base::Event>(event, mapRes.popTrace());
            }

            event->set(targetField.jsonPath(), mapRes.popPayload());

            return base::result::makeSuccess(event, mapRes.popTrace());
        };
    };
}

TransformBuilder toTransform(const OpBuilder& builder, const Reference& targetField)
{
    switch (builder.index())
    {
        case 0: return mapToTransform(std::get<0>(builder), targetField); // MapBuilder
        case 1: return std::get<1>(builder);                              // TransformBuilder
        case 2: return filterToTransform(std::get<2>(builder));           // FilterBuilder
        default: throw std::runtime_error("Invalid builder type");
    }
}

base::Expression toExpression(const TransformOp& op, const std::string& name)
{
    return base::Term<base::EngineOp>::create(name, op);
}

base::Expression baseHelperBuilder(const std::string& helperName,
                                   const Reference& targetField,
                                   std::vector<OpArg>& opArgs,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    // Resolve definition
    for (auto i = 0; i < opArgs.size(); ++i)
    {
        auto& arg = opArgs[i];
        if (arg->isReference())
        {
            auto ref = std::static_pointer_cast<Reference>(arg);
            auto isDef = buildCtx->definitions().contains(ref->jsonPath());
            if (isDef)
            {
                auto def = buildCtx->definitions().get(ref->jsonPath());
                opArgs[i] = std::make_shared<Value>(def);
            }
        }
    }

    // Obtain the builder
    auto resp = buildCtx->registry().get<OpBuilderEntry>(helperName);
    if (base::isError(resp))
    {
        throw std::runtime_error(fmt::format("Operation builder '{}' not found", helperName));
    }

    const auto& [validationInfo, builder] = base::getResponse<OpBuilderEntry>(resp);
    schemval::ValidationToken validationToken;
    // Resolve validator if needed
    if (std::holds_alternative<DynamicValToken>(validationInfo))
    {
        auto& dynamicValToken = std::get<DynamicValToken>(validationInfo);
        validationToken = dynamicValToken(opArgs, buildCtx->validator());
    }
    else
    {
        validationToken = std::get<schemval::ValidationToken>(validationInfo);
    }

    // Set operation name
    std::vector<std::string> opArgsStr;
    std::transform(
        opArgs.begin(), opArgs.end(), std::back_inserter(opArgsStr), [](const OpArg& arg) { return arg->str(); });
    auto opArgsStrJoined = base::utils::string::join(opArgsStr, ", ");
    auto name = fmt::format("{}: {}", targetField.dotPath(), helperName);
    if (!opArgsStrJoined.empty())
    {
        name += fmt::format("({})", opArgsStrJoined);
    }

    // Set new context
    auto newBuildCtx = buildCtx->clone();
    newBuildCtx->context().opName = name;

    // Apply wrappers
    base::Expression op;
    try
    {
        auto finalBuilder =
            toTransform(buildType(runType(builder, targetField, validationToken, newBuildCtx->validator()),
                                  targetField,
                                  validationToken,
                                  newBuildCtx->validator()),
                        targetField);

        op = toExpression(finalBuilder(targetField, opArgs, newBuildCtx), name);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to build operation '{}': {}", name, e.what()));
    }

    return op;
}

base::Expression
baseHelperBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx, HelperType helperType)
{
    if (!definition.isObject())
    {
        throw std::runtime_error(fmt::format("Expected 'object' type for operation definition, got '{}'",
                                             json::Json::typeToStr(definition.type())));
    }

    if (!definition.size() == 1)
    {
        throw std::runtime_error(
            fmt::format("Expected operation definition to have 1 key, got '{}'", definition.size()));
    }

    auto defObj = definition.getObject().value();

    auto [targetStr, jValue] = defObj[0];
    Reference targetField(targetStr);
    std::vector<OpArg> opArgs;
    std::string helperName;

    if (jValue.isBool() || jValue.isNumber())
    {
        // Default helper names
        switch (helperType)
        {
            case HelperType::MAP: helperName = "map"; break;
            case HelperType::FILTER: helperName = "filter"; break;
            default: throw std::runtime_error("Invalid helper type");
        }

        opArgs.emplace_back(std::make_shared<Value>(json::Json(jValue)));
    }
    else if (jValue.isString())
    {
        auto startHelperParser = detail::getHelperStartParser();
        auto strValue = jValue.getString().value();

        if (startHelperParser(strValue, 0).failure())
        {
            // Default helper names
            switch (helperType)
            {
                case HelperType::MAP: helperName = "map"; break;
                case HelperType::FILTER: helperName = "filter"; break;
                default: throw std::runtime_error("Invalid helper type");
            }
            if (strValue[0] == syntax::field::REF_ANCHOR)
            {
                opArgs.emplace_back(std::make_shared<Reference>(strValue.substr(1)));
            }
            else
            {
                json::Json argValue {};
                argValue.setString(strValue);
                opArgs.emplace_back(std::make_shared<Value>(argValue));
            }
        }
        else
        {
            auto parser = detail::getHelperParser(true);
            auto parseRes = parser(strValue, 0);

            if (parseRes.failure())
            {
                throw std::runtime_error(fmt::format("Failed to parse helper definition '{}'", strValue));
            }

            auto helperToken = parseRes.value();
            helperName = helperToken.name;

            opArgs = helperToken.args;
        }
    }
    else if (jValue.isArray())
    {
        auto arrValue = jValue.getArray().value();
        std::vector<base::Expression> subExpressions;
        for (auto i = 0; i < arrValue.size(); ++i)
        {
            auto targetFieldItem = targetField.dotPath() + "." + std::to_string(i);
            auto def = json::Json::makeObjectJson(targetFieldItem, arrValue[i]);
            subExpressions.emplace_back(baseHelperBuilder(def, buildCtx, helperType));
        }

        auto opName = fmt::format("{}: arrayExpression", targetField.dotPath());
        switch (helperType)
        {
            case HelperType::FILTER: return base::And::create(opName, subExpressions);
            default: return base::Chain::create(opName, subExpressions);
        };
    }
    else if (jValue.isObject())
    {
        auto objValue = jValue.getObject().value();
        std::vector<base::Expression> subExpressions;

        if (helperType == HelperType::MAP)
        {
            subExpressions.emplace_back(setObjectTerm(targetField.jsonPath()));
        }

        for (auto& [key, value] : objValue)
        {
            auto targetFieldItem = targetField.dotPath() + syntax::field::SEPARATOR + key;
            auto def = json::Json::makeObjectJson(targetFieldItem, value);
            subExpressions.emplace_back(baseHelperBuilder(def, buildCtx, helperType));
        }

        if (helperType == HelperType::MAP)
        {
            subExpressions.emplace_back(deleteEmptyObjectTerm(targetField.jsonPath()));
        }

        auto opName = fmt::format("{}: objectExpression", targetField.dotPath());
        switch (helperType)
        {
            case HelperType::FILTER: return base::And::create(opName, subExpressions);
            default: return base::Chain::create(opName, subExpressions);
        };
    }
    else // Null
    {
        throw std::runtime_error(
            fmt::format("Invalid type for operation definition, got '{}'", json::Json::typeToStr(jValue.type())));
    }

    auto expression = baseHelperBuilder(helperName, targetField, opArgs, buildCtx);
    return expression;
}

} // namespace builder::builders
