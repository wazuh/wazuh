#include "defs.hpp"

#include <algorithm>
#include <stack>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <fmt/format.h>

namespace defs
{
Definitions::Definitions(const json::Json& definitions)
{
    if (!definitions.isObject())
    {
        throw std::runtime_error(fmt::format("Definitions must be an object, got {}", definitions.typeName()));
    }

    auto defVars = definitions.getObject().value();
    for (const auto& [name, value] : defVars)
    {
        // TODO check definitions don't have the same name as schema fields when implemented
        // TODO move syntax from the builder to base
        if (name[0] == '$')
        {
            throw std::runtime_error(fmt::format("Definition name '{}' cannot start with '$'", name));
        }
    }

    m_definitions = std::make_unique<json::Json>(definitions);

    // Preresolve definitions to handle dependencies correctly
    preResolveDefinitions();
}

json::Json Definitions::get(std::string_view name) const
{
    auto val = m_definitions->getJson(name);
    if (!val)
    {
        throw std::runtime_error(fmt::format("Definition '{}' not found", name));
    }

    return val.value();
}

bool Definitions::contains(std::string_view name) const
{
    return m_definitions && m_definitions->exists(name);
}

std::string Definitions::replace(std::string_view input) const
{
    if (!m_definitions)
    {
        return std::string(input);
    }

    return replaceVariables(input);
}

// private
void Definitions::preResolveDefinitions()
{
    auto defObj = m_definitions->getObject().value();
    std::unordered_map<std::string, std::string> rawDefinitions;

    // Cache raw definitions as strings
    for (const auto& [name, value] : defObj)
    {
        rawDefinitions[name] = value.getString().value_or(value.str());
    }

    std::unordered_set<std::string> visited;
    std::unordered_set<std::string> inStack;
    visited.reserve(rawDefinitions.size());
    inStack.reserve(rawDefinitions.size());

    // Resolve each definition using DFS
    for (const auto& [name, _] : rawDefinitions)
    {
        if (visited.find(name) == visited.end())
        {
            resolveDefinitionDFS(name, rawDefinitions, visited, inStack);
        }
    }
}

std::string Definitions::resolveDefinitionDFS(const std::string& defName,
                                              const std::unordered_map<std::string, std::string>& rawDefs,
                                              std::unordered_set<std::string>& visited,
                                              std::unordered_set<std::string>& inStack)
{
    // If already resolved, return cached value
    if (m_resolvedDefinitions.find(defName) != m_resolvedDefinitions.end())
    {
        return m_resolvedDefinitions[defName];
    }

    // Detect circular references
    if (inStack.find(defName) != inStack.end())
    {
        throw std::runtime_error(fmt::format("Circular reference detected in definition '{}'", defName));
    }

    // Check if definition exists
    auto it = rawDefs.find(defName);
    if (it == rawDefs.end())
    {
        // Definition doesn't exist - this could be intentional, normal cases in check and parse stages
        return "$" + defName;
    }

    // Mark as visited and add to recursion stack
    visited.insert(defName);
    inStack.insert(defName);

    std::string resolved = it->second;

    // Find all $var patterns and resolve them
    size_t pos = 0;
    while ((pos = resolved.find('$', pos)) != std::string::npos)
    {
        // Check if the found $ is escaped with '\' and skip it if so
        if (pos > 0 && resolved[pos - 1] == '\\')
        {
            pos++;
            continue;
        }

        // TODO: User a helper function to validate variable names, should be moved
        // from builder to base al related to naming rules
        // Extract variable name
        size_t nameStart = pos + 1;
        size_t nameEnd = nameStart;
        // Rules should match those in the builder and parser
        while (nameEnd < resolved.length() && (std::isalnum(resolved[nameEnd]) || resolved[nameEnd] == '_'))
        {
            nameEnd++;
        }

        // Check if we found a valid variable name
        if (nameEnd <= nameStart)
        {
            pos++;
            continue;
        }

        std::string depName = resolved.substr(nameStart, nameEnd - nameStart);
        if (rawDefs.find(depName) == rawDefs.end())
        {
            // If dependency doesn't exist, leave as literal text
            // maybe a complex json value and not used for remplace strings in parser or checks
            pos = nameEnd;
        }
        else
        {
            // Recursively resolve the dependency
            std::string depValue = resolveDefinitionDFS(depName, rawDefs, visited, inStack);

            // Replace in the current definition
            resolved.replace(pos, nameEnd - pos, depValue);
            pos += depValue.length();
        }
    }

    // Remove from recursion stack and cache the resolved value
    inStack.erase(defName);
    m_resolvedDefinitions[defName] = resolved;

    return resolved;
}

std::string Definitions::replaceVariables(std::string_view input) const
{
    std::string result(input);

    // Sorted list of variable names by length (longest first)
    // This prevents shorter variable names from interfering with longer ones
    std::vector<std::pair<std::string, std::string>> sortedVars;
    sortedVars.reserve(m_resolvedDefinitions.size());

    for (const auto& [name, value] : m_resolvedDefinitions)
    {
        sortedVars.emplace_back(name, value);
    }

    // Sort by variable name length (descending) to handle prefixes correctly
    std::sort(sortedVars.begin(),
              sortedVars.end(),
              [](const auto& a, const auto& b) { return a.first.length() > b.first.length(); });

    // Process each variable in order of decreasing length
    for (const auto& [varName, varValue] : sortedVars)
    {
        std::string varPattern = "$" + varName;
        result = replaceVariableInString(result, varPattern, varValue);
    }

    return result;
}

std::string Definitions::replaceVariableInString(const std::string& input,
                                                 const std::string& varPattern,
                                                 const std::string& replacement) const
{
    std::string result = input;
    size_t pos = 0;

    while ((pos = result.find(varPattern, pos)) != std::string::npos)
    {
        // Check if the found $ is escaped with '\'
        if (pos > 0 && result[pos - 1] == '\\')
        {
            // Remove escape character and skip this occurrence
            result.erase(pos - 1, 1);
            pos += varPattern.length() - 1;
            continue;
        }

        // Check if this is a complete variable name (not part of a longer name)
        bool isCompleteVariable = true;

        // Check character after the variable name
        size_t afterPos = pos + varPattern.length();
        if (afterPos < result.length())
        {
            char nextChar = result[afterPos];
            // If next character is alphanumeric or underscore, this might be part of longer variable
            if (std::isalnum(nextChar) || nextChar == '_')
            {
                isCompleteVariable = false;
            }
        }

        if (isCompleteVariable)
        {
            // Replace the variable
            result.replace(pos, varPattern.length(), replacement);
            pos += replacement.length();
        }
        else
        {
            // Skip this occurrence as it's part of a longer variable name
            pos += varPattern.length();
        }
    }

    return result;
}

} // namespace defs
