#ifndef _DEFS_IDEFINITIONS_HPP
#define _DEFS_IDEFINITIONS_HPP

#include <memory>

#include <base/json.hpp>

namespace defs
{
class IDefinitions
{
public:
    virtual ~IDefinitions() = default;

    /**
     * @brief Get the definition json with the given dot path name.
     *
     * @param name Dot path name of the definition.
     * @return json::Json value of the definition.
     *
     * @throws std::runtime_error if the definition does not exist.
     */
    virtual json::Json get(std::string_view name) const = 0;

    /**
     * @brief Check if the definition exists.
     *
     * @param name Dot path name of the definition.
     * @return true
     * @return false
     */
    virtual bool contains(std::string_view name) const = 0;

    /**
     * @brief Search for definitions in the input string and replace them with the corresponding values.
     *
     * @param input Input string.
     * @return std::string with the definitions replaced.
     */
    virtual std::string replace(std::string_view input) const = 0;
};

class IDefinitionsBuilder
{
public:
    virtual ~IDefinitionsBuilder() = default;

    virtual std::shared_ptr<IDefinitions> build(const json::Json& value) const = 0;
};

} // namespace defs

#endif // _DEFS_IDEFINITIONS_HPP
