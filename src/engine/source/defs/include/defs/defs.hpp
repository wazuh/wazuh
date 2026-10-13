#ifndef _DEFS_HPP_
#define _DEFS_HPP_

#include <atomic>
#include <cstddef>
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
public:
    /** @brief Maximum nesting of definitions referencing definitions, same as json::Json::MAX_DEPTH */
    static constexpr std::size_t MAX_DEPTH = json::Json::MAX_DEPTH;
    /** @brief Maximum size of a definition after its references are expanded */
    static constexpr std::size_t MAX_EXPANDED_SIZE = 64 * 1024;
    /** @brief Maximum bytes added by expansion across all definitions and every replace() call */
    static constexpr std::size_t MAX_TOTAL_EXPANSION = 1024 * 1024;

private:
    /** @brief pre-resolved definitions to handle dependencies in string replacement */
    std::unordered_map<std::string, std::string> m_resolvedDefinitions;
    std::unique_ptr<json::Json> m_definitions;            ///< JSON object with the definitions as key-value pairs
    mutable std::atomic<std::size_t> m_expandedBytes {0}; ///< Bytes added by expansion, capped at MAX_TOTAL_EXPANSION

    /**
     * @brief Account for @p added bytes of expansion
     *
     * @throws std::runtime_error if the total exceeds MAX_TOTAL_EXPANSION
     */
    void addExpansion(std::size_t added) const;

    /**
     * @brief Pre-resolve all definitions to handle dependencies correctly
     */
    void preResolveDefinitions();

    /**
     * @brief Resolve a single definition using DFS with cycle detection
     *
     * @throws std::runtime_error on a cycle, or if MAX_DEPTH, MAX_EXPANDED_SIZE or MAX_TOTAL_EXPANSION is exceeded
     */
    std::string resolveDefinitionDFS(const std::string& defName,
                                     const std::unordered_map<std::string, std::string>& rawDefs,
                                     std::unordered_set<std::string>& visited,
                                     std::unordered_set<std::string>& inStack,
                                     std::unordered_map<std::string, std::size_t>& depths);

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
