#include "normalize.hpp"

#include <algorithm>
#include <unordered_map>

#include <base/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

namespace
{
/**
 * @brief Preprocess the parse stage when using the format parse|$field
 *
 * This function checks if the key matches the format parse|$field, where $field is a DotPath.
 * If it matches, the key is modified to "parse" and the value is transformed into an array of
 * objects, each object containing the original parse definition and the target field.
 * This preprocessing is necessary to adapt the user-friendly format into the expected format for the parse stage.
 * @param key Key of the subblock, can be parse|$field with $field a DotPath, the key will be modified to "parse" if it
 * matches the format
 * @param value Value of the subblock (Array of strings, each string is a parse definition)
 * @return json::Json Adapted value for the parse subblock, or empty if not a parse|$field case
 */
json::Json preProcessParseStage(std::string& key, json::Json& value)
{
    json::Json stageParseValue;
    stageParseValue.setArray();

    const size_t keySize = strlen(syntax::asset::PARSE_KEY);
    if (key.compare(0, keySize, syntax::asset::PARSE_KEY) != 0)
    {
        return stageParseValue; // Not a parse|$field case
    }

    const bool meetsFormat = key.length() > keySize && key[keySize] == '|';
    if (!meetsFormat)
    {
        throw std::runtime_error("Stage parse: needs the character '|' to indicate the field");
    }

    // Extract text after '|'
    const auto targetField = key.substr(keySize + 1);

    try
    {
        DotPath {targetField};
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Stage parse: Could not get field: '{}'", e.what()));
    }

    key = syntax::asset::PARSE_KEY; // Overwrite key to "parse"
    if (!value.isArray())
    {
        throw std::runtime_error("Stage parse: expects an array of strings as value");
    }
    const auto arr = value.getArray().value();
    for (const auto& item : arr)
    {
        json::Json tmp;
        tmp.setObject();
        const auto parseValue = item.getString().value();
        tmp.setString(parseValue, json::Json::formatJsonPath(targetField, true));
        stageParseValue.appendJson(tmp);
    }

    return stageParseValue;
}

/**
 * @brief Get the builder for a given stage subblock
 * @param key Stage name (parse, check, map)
 * @param buildCtx Build context
 * @return StageBuilder Builder function for the stage
 * @throw std::runtime_error if the stage is not supported or the builder is not found
 */
StageBuilder getStageBuilder(const std::string& key, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (key != syntax::asset::PARSE_KEY && key != syntax::asset::CHECK_KEY && key != syntax::asset::MAP_KEY)
    {
        throw std::runtime_error(
            fmt::format("In stage '{}' block '{}' is not supported", syntax::asset::NORMALIZE_KEY, key));
    }

    auto builderResp = buildCtx->registry().get<StageBuilder>(key);
    if (base::isError(builderResp))
    {
        throw std::runtime_error(
            fmt::format("In stage '{}' builder for block '{}' not found", syntax::asset::NORMALIZE_KEY, key));
    }

    return base::getResponse<StageBuilder>(builderResp);
}

/**
 * @brief
 * @param keyValueTuple Tupla clave-valor del subblock
 * @param buildCtx Contexto de construcción
 * @return Expresión generada para el subblock
 */
base::Expression processSubBlock(std::tuple<std::string, json::Json>& keyValueTuple,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto& [key, value] = keyValueTuple;

    // Procesar casos especiales de parse|VARIABLE
    json::Json stageParseValue = preProcessParseStage(key, value);

    //
    if (key == syntax::asset::PARSE_KEY && !stageParseValue.getArray().value().empty())
    {
        value = std::move(stageParseValue);
    }

    // Get the builder for the stage
    const auto builder = getStageBuilder(key, buildCtx);

    try
    {
        return builder(value, buildCtx);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format(
            "In stage '{}' builder for block '{}' failed with error: {}", syntax::asset::NORMALIZE_KEY, key, e.what()));
    }
}

/**
 * @brief Get the normalized key for order validation
 * @param key Original key that might be in format parse|field
 * @return Normalized key (parse|field becomes parse)
 */
std::string getNormalizedKeyForOrder(const std::string& key)
{
    const size_t keySize = strlen(syntax::asset::PARSE_KEY);
    if (key.compare(0, keySize, syntax::asset::PARSE_KEY) == 0 && key.length() > keySize && key[keySize] == '|')
    {
        return syntax::asset::PARSE_KEY;
    }
    return key;
}

/**
 * @brief Proccess an item of the normalize stage
 *
 * The block must be an object with subblocks,
 * each subblock is processed and combined with an AND operation.
 * @param block Item to process
 * @param buildCtx Build context
 * @return base::Expression Expression of the item
 * @note The order of subblocks should be check, parse, map. Each subblock is optional.
 */
base::Expression processItem(const json::Json& block, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!block.isObject())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an array of objects but got an item of type '{}'",
                                             syntax::asset::NORMALIZE_KEY,
                                             block.typeName()));
    }

    auto blockObj = block.getObject().value();
    std::vector<base::Expression> subBlocksExpressions;

    // Check the order of subblocks
    const std::unordered_map<std::string, int> orderMap = {
        {syntax::asset::CHECK_KEY, 0}, {syntax::asset::PARSE_KEY, 1}, {syntax::asset::MAP_KEY, 2}};

    int lastOrder = -1;
    for (const auto& [key, _] : blockObj)
    {
        // Normalize the key for order validation (parse|field -> parse)
        const std::string normalizedKey = getNormalizedKeyForOrder(key);
        auto it = orderMap.find(normalizedKey);

        if (it != orderMap.end())
        {
            if (it->second < lastOrder)
            {
                throw std::runtime_error(fmt::format("Stage '{}': subblocks must be in order: check, parse, map",
                                                     syntax::asset::NORMALIZE_KEY));
            }
            lastOrder = it->second;
        }
    }

    // Process each subblock of the item
    std::transform(blockObj.begin(),
                   blockObj.end(),
                   std::back_inserter(subBlocksExpressions),
                   [buildCtx](auto& keyValueTuple) { return processSubBlock(keyValueTuple, buildCtx); });

    return base::And::create("normalize-item", subBlocksExpressions);
}
} // namespace

base::Expression normalizeBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!definition.isArray())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects an array or string but got '{}'", syntax::asset::NORMALIZE_KEY, definition.typeName()));
    }

    const auto blocks = definition.getArray().value();
    if (blocks.empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects at least one block", syntax::asset::NORMALIZE_KEY));
    }

    std::vector<base::Expression> blockExpressions;

    // Procces each iteam of the normalize
    std::transform(blocks.begin(),
                   blocks.end(),
                   std::back_inserter(blockExpressions),
                   [buildCtx](const auto& block) { return processItem(block, buildCtx); });

    return base::Chain::create("normalize", blockExpressions);
}

} // namespace builder::builders
