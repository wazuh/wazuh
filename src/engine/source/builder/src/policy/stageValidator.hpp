#ifndef BUILDER_POLICY_STAGEVALIDATOR_HPP
#define BUILDER_POLICY_STAGEVALIDATOR_HPP

#include <algorithm>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>
#include <base/dotPath.hpp>
#include <fmt/format.h>

#include "syntax.hpp"

namespace builder::policy
{

namespace detail
{

inline bool startsWith(const std::string& value, std::string_view prefix)
{
    return std::string_view(value).substr(0, prefix.size()) == prefix;
}

struct StageRule
{
    const char* name;
    bool isPrefix;
};

struct AssetStageRules
{
    const char* description;
    std::vector<StageRule> rules;
};

static constexpr char PARSE_STAGE_PREFIX[] = "parse|";
static constexpr std::size_t PARSE_STAGE_PREFIX_SIZE = sizeof(PARSE_STAGE_PREFIX) - 1;

inline const AssetStageRules& allowedStageRules(const std::string& assetType)
{
    static const AssetStageRules decoderRules {
        "check, parse|<field>, normalize",
        {{syntax::asset::CHECK_KEY, false},
         {PARSE_STAGE_PREFIX, true},
         {syntax::asset::NORMALIZE_KEY, false}}};

    static const AssetStageRules filterRules {
        "check",
        {{syntax::asset::CHECK_KEY, false}}};

    static const AssetStageRules outputRules {
        "check, outputs",
        {{syntax::asset::CHECK_KEY, false},
         {syntax::asset::OUTPUTS_KEY, false}}};

    if (assetType == "decoder")
    {
        return decoderRules;
    }

    if (assetType == "filter")
    {
        return filterRules;
    }

    if (assetType == "output")
    {
        return outputRules;
    }

    throw std::runtime_error(fmt::format("Unknown asset type '{}'", assetType));
}

inline bool isAllowedStage(const std::string& stage, const AssetStageRules& rules)
{
    return std::any_of(rules.rules.begin(),
                       rules.rules.end(),
                       [&stage](const auto& rule)
                       {
                           if (rule.isPrefix)
                           {
                               return startsWith(stage, rule.name);
                           }

                           return stage == rule.name;
                       });
}

inline std::string assetTypeName(const base::Name& name)
{
    if (syntax::name::isDecoder(name))
    {
        return "decoder";
    }

    if (syntax::name::isFilter(name))
    {
        return "filter";
    }

    if (syntax::name::isOutput(name))
    {
        return "output";
    }

    throw std::runtime_error(fmt::format("Unknown asset type for asset '{}'", name.toStr()));
}

inline const char* allowedStages(const std::string& assetType)
{
    return allowedStageRules(assetType).description;
}

inline void throwInvalidStage(const std::string& stage, const base::Name& assetName, const std::string& assetType)
{
    throw std::runtime_error(fmt::format("Invalid stage '{}' for {} asset '{}'. Allowed stages: {}",
                                         stage,
                                         assetType,
                                         assetName.toStr(),
                                         allowedStages(assetType)));
}

inline bool isSupportedOutputOperation(const std::string& operation)
{
    return operation == syntax::asset::FIRST_OF_KEY || operation == syntax::asset::FILE_OUTPUT_KEY
           || operation == syntax::asset::INDEXER_OUTPUT_KEY;
}

inline void validateOutputsStage(const json::Json& outputs, const base::Name& assetName)
{
    const auto arr = outputs.getArray();

    if (!arr)
    {
        throw std::runtime_error(
            fmt::format("Invalid outputs stage for output asset '{}'. Expected a non-empty array of objects",
                        assetName.toStr()));
    }

    if (arr.value().empty())
    {
        throw std::runtime_error(
            fmt::format("Invalid outputs stage for output asset '{}'. Expected a non-empty array of objects",
                        assetName.toStr()));
    }

    for (const auto& item : arr.value())
    {
        const auto obj = item.getObject();

        if (!obj)
        {
            throw std::runtime_error(
                fmt::format("Invalid outputs stage for output asset '{}'. Expected every item to be an object",
                            assetName.toStr()));
        }

        if (obj.value().size() != 1)
        {
            throw std::runtime_error(
                fmt::format("Invalid outputs stage for output asset '{}'. Each item must contain exactly one operation",
                            assetName.toStr()));
        }

        for (const auto& operationEntry : obj.value())
        {
            const auto& operation = std::get<0>(operationEntry);

            if (!isSupportedOutputOperation(operation))
            {
                throw std::runtime_error(
                    fmt::format("Invalid output operation '{}' for output asset '{}'.\nAllowed operations: {}, {}, {}",
                                operation,
                                assetName.toStr(),
                                syntax::asset::FIRST_OF_KEY,
                                syntax::asset::FILE_OUTPUT_KEY,
                                syntax::asset::INDEXER_OUTPUT_KEY));
            }
        }
    }
}

inline void validateDecoderStage(const std::string& stage, const base::Name& assetName)
{
    const auto& rules = allowedStageRules("decoder");
    if (!isAllowedStage(stage, rules))
    {
        throwInvalidStage(stage, assetName, "decoder");
    }

    if (!startsWith(stage, PARSE_STAGE_PREFIX))
    {
        return;
    }

    const auto field = stage.substr(PARSE_STAGE_PREFIX_SIZE);

    if (field.empty())
    {
        throw std::runtime_error(fmt::format(
            "Invalid parse stage '{}' for decoder asset '{}': missing field. Expected format: parse|<field>",
            stage,
            assetName.toStr()));
    }

    try
    {
        DotPath {field};
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Invalid parse stage '{}' for decoder asset '{}': {}", stage, assetName.toStr(), e.what()));
    }
}

inline void validateFilterStage(const std::string& stage, const base::Name& assetName)
{
    const auto& rules = allowedStageRules("filter");
    if (!isAllowedStage(stage, rules))
    {
        throwInvalidStage(stage, assetName, "filter");
    }

}

inline void validateOutputStage(const std::string& stage, const json::Json& value, const base::Name& assetName)
{
    const auto& rules = allowedStageRules("output");
    if (!isAllowedStage(stage, rules))
    {
        throwInvalidStage(stage, assetName, "output");
    }

    if (stage == syntax::asset::OUTPUTS_KEY)
    {
        validateOutputsStage(value, assetName);
    }

}

} // namespace detail

inline void validateStages(const base::Name& assetName, const std::vector<std::tuple<std::string, json::Json>>& stages)
{
    const auto assetType = detail::assetTypeName(assetName);

    for (const auto& [stage, value] : stages)
    {
        if (stage == syntax::asset::DEFINITIONS_KEY)
        {
            continue;
        }

        if (assetType == "decoder")
        {
            detail::validateDecoderStage(stage, assetName);
        }
        else if (assetType == "filter")
        {
            detail::validateFilterStage(stage, assetName);
        }
        else if (assetType == "output")
        {
            detail::validateOutputStage(stage, value, assetName);
        }
    }
}

} // namespace builder::policy

#endif // BUILDER_POLICY_STAGEVALIDATOR_HPP

