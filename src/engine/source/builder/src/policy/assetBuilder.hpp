#ifndef _BUILDER_POLICY_ASSETBUILDER_HPP
#define _BUILDER_POLICY_ASSETBUILDER_HPP

#include <defs/idefinitions.hpp>

#include "builders/buildCtx.hpp"
#include "iassetBuilder.hpp"
#include "iregistry.hpp"

namespace builder::policy
{

/**
 * @brief Class that builds assets from store documents.
 *
 */
class AssetBuilder : public IAssetBuilder
{
private:
    std::shared_ptr<builders::BuildCtx> m_buildCtx;                  ///< Initial build context
    std::shared_ptr<defs::IDefinitionsBuilder> m_definitionsBuilder; ///< Definitions builder

public:
    /**
     * @brief Construct a new Asset Builder object
     *
     * @param buildCtx Initial build context
     * @param definitionsBuilder Definitions builder
     */
    AssetBuilder(const std::shared_ptr<builders::BuildCtx>& buildCtx,
                 const std::shared_ptr<defs::IDefinitionsBuilder>& definitionsBuilder)
        : m_buildCtx(buildCtx)
        , m_definitionsBuilder(definitionsBuilder)
    {
    }

    /**
     * @brief Obtain the name of the asset from a Json value.
     *
     * @param value Json value of the name
     *
     * @return base::Name
     *
     * @throw std::runtime_error If the value does not contain a valid name.
     */
    base::Name getName(const json::Json& value) const;

    /**
     * @brief Obtain the parents of the asset from a Json value.
     *
     * @param value Json value of the parents
     *
     * @return std::vector<base::Name>
     *
     * @throw std::runtime_error If the value does not contain a valid array of names.
     */
    std::vector<base::Name> getParents(const json::Json& value) const;

    /**
     * @brief Build the expression of the asset from the object containing the asset stages.
     *
     * If no stages are found, defaults to an asset that always succeeds and does nothing.
     *
     * @param name Name of the asset to be used in the expression.
     * @param objDoc Object containing the asset stages.
     *
     * @return base::Expression
     *
     * @throw std::runtime_error If any error occurs while building the stages.
     */
    base::Expression buildExpression(const base::Name& name,
                                     std::vector<std::tuple<std::string, json::Json>>& objDoc) const;

    /**
     * @copydoc IAssetBuilder::operator()
     */
    Asset operator()(const store::Doc& document) const override;
};

} // namespace builder::policy

#endif // _BUILDER_POLICY_ASSETBUILDER_HPP
