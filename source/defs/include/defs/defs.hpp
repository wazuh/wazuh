#ifndef _DEFS_HPP_
#define _DEFS_HPP_

#include <memory>
#include <string>
#include <string_view>

#include <defs/idefinitions.hpp>
#include <json/json.hpp>

/**
 * @brief Namespace for the component definitions
 *
 */
namespace defs
{
class Definitions : public IDefinitions
{
private:
    std::unique_ptr<json::Json> m_definitions;

public:
    Definitions() = default;
    ~Definitions() = default;

    /**
     * @brief Construct a new Definitions object
     *
     * @param definitions JSON object with the definitions.
     */
    explicit Definitions(const json::Json& definitions);

    /**
     * @copydoc IDefinitions::contains
     */
    bool contains(std::string_view name) const override;

    /**
     * @copydoc IDefinitions::get
     */
    json::Json get(std::string_view name) const override;
};
} // namespace defs

#endif // _DEFS_HPP_
