#ifndef _BUILDER2_IPOLICY_HPP
#define _BUILDER2_IPOLICY_HPP

#include <unordered_set>

#include <expression.hpp>
#include <name.hpp>

namespace builder
{

class IPolicy
{
public:
    virtual ~IPolicy() = default;

    /**
     * @brief Get the policy name.
     *
     * @return base::Name
     */
    virtual const base::Name& name() const = 0;

    /**
     * @brief Get the policy hash.
     *
     * @return std::string Hash of the policy.
     */
    virtual const std::string& hash() const = 0;

    /**
     * @brief Get the policy assets.
     *
     * @return std::unordered_set<base::Name>
     */
    virtual const std::unordered_set<base::Name>& assets() const = 0;

    /**
     * @brief Get the policy expression.
     *
     * @return base::Expression
     */
    virtual const base::Expression& expression() const = 0;

    /**
     * @brief Get the Graphivz Str object
     *
     * @return std::string
     */
    virtual std::string getGraphivzStr() const = 0;
};

} // namespace builder

#endif // _BUILDER2_IPOLICY_HPP
