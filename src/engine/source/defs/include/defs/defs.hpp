#ifndef _DEFS_HPP_
#define _DEFS_HPP_

#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include <base/json.hpp>
#include <defs/idefinitions.hpp>

/**
 * @brief Namespace for the component definitions
 *
 */
namespace defs
{
class Definitions : public IDefinitions
{
private:
    /** @brief pre-resolved definitions to handle dependencies in string replacement */
    std::unordered_map<std::string, std::string> m_resolvedDefinitions;
    std::unique_ptr<json::Json> m_definitions; ///< JSON object with the definitions as key-value pairs

    /**
     * @brief Pre-resolve all definitions to handle dependencies correctly
     */
    void preResolveDefinitions();

    /**
     * @brief Resolve a single definition using DFS with cycle detection
     */
    std::string resolveDefinitionDFS(const std::string& defName,
                                     const std::unordered_map<std::string, std::string>& rawDefs,
                                     std::unordered_set<std::string>& visited,
                                     std::unordered_set<std::string>& inStack);

    /**
     * @brief Improved variable replacement algorithm that handles prefix conflicts
     */
    std::string replaceVariables(std::string_view input) const;

    /**
     * @brief Replace a specific variable pattern in a string with proper boundary checking
     */
    std::string replaceVariableInString(const std::string& input,
                                        const std::string& varPattern,
                                        const std::string& replacement) const;

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

    /**
     * @copydoc IDefinitions::replace
     */
    std::string replace(std::string_view input) const override;
};

class DefinitionsBuilder : public IDefinitionsBuilder
{
public:
    DefinitionsBuilder() = default;
    ~DefinitionsBuilder() = default;

    std::shared_ptr<IDefinitions> build(const json::Json& value) const override
    {
        return std::make_shared<Definitions>(value);
    }
};

} // namespace defs

#endif // _DEFS_HPP_
