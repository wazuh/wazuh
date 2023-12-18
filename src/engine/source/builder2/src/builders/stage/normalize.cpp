#include "normalize.hpp"

#include <algorithm>
#include <unordered_map>

#include <json/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

const std::string PARSE_PREFIX {"parse|"};

base::Expression normalizeBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!definition.isArray())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects an array or string but got '{}'", syntax::asset::NORMALIZE_KEY, definition.typeName()));
    }

    auto blocks = definition.getArray().value();
    std::vector<base::Expression> blockExpressions;
    // Normalize blocks
    std::transform(
        blocks.begin(),
        blocks.end(),
        std::back_inserter(blockExpressions),
        [buildCtx](auto block)
        {
            if (!block.isObject())
            {
                throw std::runtime_error(
                    fmt::format("Stage '{}' expects an array of objects but got an item of type '{}'",
                                syntax::asset::NORMALIZE_KEY,
                                block.typeName()));
            }
            auto blockObj = block.getObject().value();
            std::vector<base::Expression> subBlocksExpressions;

            // Stages in a block (subblocks)
            std::transform(
                blockObj.begin(),
                blockObj.end(),
                std::back_inserter(subBlocksExpressions),
                [buildCtx](auto& tuple)
                {
                    auto& [key, value] = tuple;
                    json::Json stageParseValue;
                    stageParseValue.setArray();
                    auto pos = key.find(PARSE_PREFIX);
                    if (pos != std::string::npos)
                    {
                        // TODO fix this hack, we need to format the json as the old parse stage
                        auto parseKey = key.substr(pos + PARSE_PREFIX.size());
                        key = "parse";
                        if (value.isArray())
                        {
                            json::Json tmp;
                            tmp.setObject();
                            auto arr = value.getArray().value();
                            for (size_t i = 0; i < arr.size(); i++)
                            {
                                auto parseValue = arr[i].getString().value();
                                tmp.setString(parseValue, json::Json::formatJsonPath(parseKey, true));
                                stageParseValue.appendJson(tmp);
                            }
                        }
                    }

                    base::RespOrError<StageBuilder> builderResp;
                    if (key == "parse")
                    {
                        value = std::move(stageParseValue);
                        builderResp = buildCtx->registry().get<StageBuilder>("parse");
                    }
                    else
                    {
                        if (key != syntax::asset::CHECK_KEY && key != syntax::asset::MAP_KEY)
                        {
                            throw std::runtime_error(fmt::format(
                                "In stage '{}' block '{}' is not supported", syntax::asset::NORMALIZE_KEY, key));
                        }
                        builderResp = buildCtx->registry().get<StageBuilder>(key);
                    }

                    if (base::isError(builderResp))
                    {
                        throw std::runtime_error(fmt::format(
                            "In stage '{}' builder for block '{}' not found", syntax::asset::NORMALIZE_KEY, key));
                    }

                    auto builder = base::getResponse<StageBuilder>(builderResp);
                    try
                    {
                        return builder(value, buildCtx);
                    }
                    catch (const std::exception& e)
                    {
                        throw std::runtime_error(
                            fmt::format("In stage '{}' builder for block '{}' failed with error: {}",
                                        syntax::asset::NORMALIZE_KEY,
                                        key,
                                        e.what()));
                    }
                });
            auto expression = base::And::create("subblock", subBlocksExpressions);
            return expression;
        });
    auto expression = base::Chain::create("normalize", blockExpressions);
    return expression;
}

} // namespace builder::builders
