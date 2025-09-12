#ifndef _BUILDER_POLICY_ASSET_HPP
#define _BUILDER_POLICY_ASSET_HPP

#include <vector>

#include <base/expression.hpp>

namespace builder::policy
{

/**
 * @brief Class representing a built asset
 *
 */
class Asset
{
private:
    base::Name m_name;                 ///< Asset name
    base::Expression m_expression;     ///< Asset expression
    std::vector<base::Name> m_parents; ///< Asset parents

public:
    Asset() = default;

    /**
     * @brief Construct a new Asset object
     *
     * @param name Name of the asset
     * @param expression Expression of the asset
     * @param parents Parents of the asset
     */
    Asset(base::Name&& name, base::Expression&& expression, std::vector<base::Name>&& parents)
        : m_name(std::move(name))
        , m_expression(std::move(expression))
        , m_parents(std::move(parents))
    {
    }

    /**
     * @brief Get the name of the asset
     *
     * @return const base::Name&
     */
    inline const base::Name& name() const { return m_name; }

    /**
     * @brief Get the expression of the asset
     *
     * @return const base::Expression&
     */
    inline const base::Expression& expression() const { return m_expression; }

    /**
     * @brief Get the parents of the asset
     *
     * @return const std::vector<base::Name>&
     */
    inline const std::vector<base::Name>& parents() const { return m_parents; }
    std::vector<base::Name>& parents() { return m_parents; }

    friend bool operator==(const Asset& lhs, const Asset& rhs)
    {
        return lhs.m_name == rhs.m_name && lhs.m_expression == rhs.m_expression && lhs.m_parents == rhs.m_parents;
    }
};

} // namespace builder::policy

#endif // _BUILDER_POLICY_ASSET_HPP
