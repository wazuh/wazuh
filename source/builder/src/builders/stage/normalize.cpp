#include "normalize.hpp"

#include <algorithm>
#include <unordered_map>

#include <base/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

base::Expression normalizeBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!definition.isArray())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects an array or string but got '{}'", syntax::asset::NORMALIZE_KEY, definition.typeName()));
    }

    auto blocks = definition.getArray().value();
    if (blocks.empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects at least one block", syntax::asset::NORMALIZE_KEY));
    }

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
                    json::Json stageParseValue;
                    stageParseValue.setArray();
                    auto& [key, value] = tuple;
                    size_t keySize = strlen(syntax::asset::PARSE_KEY);
                    if (key.compare(0, keySize, syntax::asset::PARSE_KEY) == 0)
                    {
                        bool meetsFormat = key.length() > keySize && key[keySize] == '|';

                        if (!meetsFormat)
                        {
                            throw std::runtime_error("Stage parse: needs the character '|' to indicate the field");
                        }

                        // Extract text after '|'
                        auto targetField = key.substr(keySize + 1);

                        try
                        {
                            DotPath {targetField};
                        }
                        catch (const std::exception& e)
                        {
                            throw std::runtime_error(fmt::format("Stage parse: Could not get field: {}", e.what()));
                        }

                        key = "parse";
                        if (value.isArray())
                        {
                            json::Json tmp;
                            tmp.setObject();
                            auto arr = value.getArray().value();
                            for (size_t i = 0; i < arr.size(); i++)
                            {
                                auto parseValue = arr[i].getString().value();
                                tmp.setString(parseValue, json::Json::formatJsonPath(targetField, true));
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
