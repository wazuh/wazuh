#ifndef _ASSET_H
#define _ASSET_H

#include <string>
#include <unordered_set>

#include <fmt/format.h>

#include "definitions.hpp"
#include "expression.hpp"
#include <json/json.hpp>
#include "registry.hpp"

namespace builder
{

/**
 * @brief Intermediate representation of the Asset.
 *
 * The Asset contains the following information:
 * - The name of the asset.
 * - The type of the asset (decoder, rule, output, filter).
 * - The list of parents of the asset, stored in a set.
 * - Metadata about the asset, as a JSON object.
 * - The expression of the check part (check, parse) of the asset.
 * - The expression of the rest of stages in the asset.
 *
 * @warning Stages check and parse are builded first in said order, ignoring the
 * order in the JSON object.
 */
class Asset
{
public:
    /**
     * @brief Type of Asset.
     *
     */
    enum class Type
    {
        DECODER,
        RULE,
        OUTPUT,
        FILTER
    };

    std::string m_name;
    base::Expression m_check;
    base::Expression m_stages;
    Type m_type;
    std::unordered_set<std::string> m_parents;
    json::Json m_metadata;

    /**
     * @brief Get the type name.
     *
     * @param type
     * @return std::string
     * @throws std::runtime_error if the type is unknown.
     */
    static std::string typeToString(Type type);

    /**
     * @brief Construct a new Empty Asset object
     *
     * @param name Name of the asset.
     * @param type Type of the asset.
     */
    Asset(std::string name, Type type);

    /**
     * @brief Construct a new Asset object from a JSON object.
     *
     * @warning Stages check and parse are builded first in said order, ignoring the order
     * in the JSON object.
     *
     * @param jsonDefinition JSON object containing the definition of the asset.
     * @param type Type of the asset.
     * @throws std::runtime_error if the Asset could not be constructed.
     */
    Asset(const json::Json& jsonDefinition, Type type);

    /**
     * @brief Get the Expression object of the Asset.
     *
     * @return base::Expression
     * @throws std::runtime_error if the Expression could not be constructed.
     */
    base::Expression getExpression() const;
};

} // namespace builder

#endif // _ASSET_H
