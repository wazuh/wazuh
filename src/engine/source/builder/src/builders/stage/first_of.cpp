#include "first_of.hpp"

#include <algorithm>

#include <base/json.hpp>

#include "syntax.hpp"

namespace builder::builders
{

namespace
{

/**
 * @brief Process a "then" action definition
 *
 * Validates the JSON structure (must be array of output objects)
 * and builds the corresponding output expressions by looking up builders
 * in the registry. Only "wazuh-indexer" and "file" outputs are supported.
 *
 * @param thenDefinition JSON array like [{"wazuh-indexer": {"index": "..."}}]
 * @param buildCtx Build context with registry access
 * @param contextName Context name for error messages (e.g., "first_of.item-0")
 * @return base::Expression The built output expression (Broadcast if multiple, single if one)
 * @throw std::runtime_error if validation fails or builder not found
 */
base::Expression processThenAction(const json::Json& thenDefinition,
                                   const std::shared_ptr<const IBuildCtx>& buildCtx,
                                   const std::string& contextName)
{
    if (!thenDefinition.isArray())
    {
        throw std::runtime_error(
            fmt::format("{}: 'then' expects an array but got '{}'", contextName, thenDefinition.typeName()));
    }

    auto thenArray = thenDefinition.getArray().value();
    if (thenArray.empty())
    {
        throw std::runtime_error(fmt::format("{}: 'then' expects at least one output", contextName));
    }

    std::vector<base::Expression> thenExpressions;
    for (const auto& outputItem : thenArray)
    {
        if (!outputItem.isObject())
        {
            throw std::runtime_error(
                fmt::format("{}: 'then' array items must be objects but got '{}'", contextName, outputItem.typeName()));
        }

        auto outputObj = outputItem.getObject().value();
        if (outputObj.size() != 1)
        {
            throw std::runtime_error(fmt::format(
                "{}: 'then' array items must have exactly one key-value pair but got {}", contextName, outputObj.size()));
        }

        const auto& [outputType, outputDefinition] = *outputObj.begin();
        // TODO: Find a better way to filter allowed assets per stage.
        if (outputType != syntax::asset::INDEXER_OUTPUT_KEY && outputType != syntax::asset::FILE_OUTPUT_KEY)
        {
            throw std::runtime_error(
                fmt::format("{}: unsupported output type '{}'", contextName, outputType));
        }

        auto builderResp = buildCtx->registry().get<StageBuilder>(outputType);
        if (base::isError(builderResp))
        {
            throw std::runtime_error(fmt::format("{}: unknown output type '{}'", contextName, outputType));
        }

        auto builder = base::getResponse<StageBuilder>(builderResp);
        try
        {
            thenExpressions.push_back(builder(outputDefinition, buildCtx));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("{}: failed to build output '{}': {}", contextName, outputType, e.what()));
        }
    }

    return base::Broadcast::create(fmt::format("{}.then", contextName), thenExpressions);
}

/**
 * @brief Process a single item from first_of array
 *
 * Validates the item structure (must have "check" and "then" keys),
 * builds both expressions, and combines them into an Implication.
 *
 * @param itemDefinition JSON object like {"check": [...], "then": {...}}
 * @param itemIndex Index in array (for error messages and naming)
 * @param buildCtx Build context
 * @return base::Expression Implication(check, then)
 * @throw std::runtime_error if validation fails
 */
base::Expression processItem(const json::Json& itemDefinition,
                             int itemIndex,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    auto itemName = fmt::format("first_of.item-{}", itemIndex);

    if (!itemDefinition.isObject())
    {
        throw std::runtime_error(
            fmt::format("{}: item must be an object but got '{}'", itemName, itemDefinition.typeName()));
    }

    auto itemObj = itemDefinition.getObject().value();
    if (itemObj.size() != 2)
    {
        throw std::runtime_error(
            fmt::format("{}: item must have exactly 'check' and 'then' keys but has {}", itemName, itemObj.size()));
    }

    const auto& [keyCheck, valueCheck] = itemObj[0];
    if (keyCheck != syntax::asset::CHECK_KEY)
    {
        throw std::runtime_error(fmt::format("{}: item missing 'check' key", itemName));
    }

    const auto& [keyThen, valueThen] = itemObj[1];
    if (keyThen != syntax::asset::THEN_KEY)
    {
        throw std::runtime_error(fmt::format("{}: item missing 'then' key", itemName));
    }

    base::Expression checkExpr {};
    try
    {
        auto checkBuilderResp = buildCtx->registry().get<StageBuilder>(syntax::asset::CHECK_KEY);
        if (base::isError(checkBuilderResp))
        {
            throw std::runtime_error("check builder not found in registry");
        }
        auto checkBuilder = base::getResponse<StageBuilder>(checkBuilderResp);
        checkExpr = checkBuilder(valueCheck, buildCtx);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("{}: failed to build check: {}", itemName, e.what()));
    }

    base::Expression thenExpr {};
    try
    {
        thenExpr = processThenAction(valueThen, buildCtx, itemName);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("{}: failed to build then: {}", itemName, e.what()));
    }

    return base::Implication::create(itemName, checkExpr, thenExpr);
}

} // namespace

/**
 * @brief Build a "first_of" stage expression from JSON definition
 *
 * Processes an array of items, each with "check" and "then".
 * It evaluates each "check" in order and returns the "then" of the first true "check".
 *
 * @param definition JSON array of items, each with "check" and "then"
 * @param buildCtx Build context
 * @return base::Expression Combined expression representing first_of logic
 */
base::Expression firstOfBuilder(const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    if (!definition.isArray())
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects an array but got '{}'", syntax::asset::FIRST_OF_KEY, definition.typeName()));
    }

    const auto items = definition.getArray().value();
    if (items.empty())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects a non-empty array", syntax::asset::FIRST_OF_KEY));
    }

    std::vector<base::Expression> itemImplications;
    for (size_t i = 0; i < items.size(); ++i)
    {
        try
        {
            auto implication = processItem(items[i], static_cast<int>(i), buildCtx);
            itemImplications.push_back(implication);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Stage '{}' failed to process item {}: {}", syntax::asset::FIRST_OF_KEY, i, e.what()));
        }
    }

    return base::Or::create("first_of", itemImplications);
}

} // namespace builder::builders
