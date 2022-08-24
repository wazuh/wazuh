#include "definitions.hpp"

#include <algorithm>

#include "syntax.hpp"
#include <fmt/format.h>

namespace
{
void substituteDefinition(const std::string& key,
                          const std::string& value,
                          std::string& text)
{
    size_t pos = 0;
    while ((pos = text.find(key, pos)) != std::string::npos)
    {
        text.replace(pos, key.length(), value);
        pos += value.length();
    }
}
} // namespace

namespace builder::internals
{

using namespace json;

constexpr auto DEFINITIONS_KEY = "/definitions";

void substituteDefinitions(Json& asset)
{
    if (!asset.isObject())
    {
        throw std::runtime_error(
            fmt::format("[substituteDefinitions(asset)] Expected object, got [{}]",
                        asset.typeName()));
    }

    if (asset.exists(DEFINITIONS_KEY))
    {
        if (!asset.isObject(DEFINITIONS_KEY))
        {
            // TODO: add getTypeName with path to Json
            throw std::runtime_error(
                fmt::format("[substituteDefinitions(asset)] Expected object, got [{}]",
                            "not_implemented"));
        }

        auto definitionsObject = asset.getObject(DEFINITIONS_KEY).value();
        if (!asset.erase(DEFINITIONS_KEY))
        {
            throw std::runtime_error(fmt::format(
                "[substituteDefinitions(asset)] Could not erase [{}]", DEFINITIONS_KEY));
        }

        // Definitions can reference other definitions, so we need to check other
        // definitions as well.
        for (auto& [key, value] : definitionsObject)
        {
            for (auto& [key2, value2] : definitionsObject)
            {
                if (key != key2)
                {
                    auto formatKey = syntax::REFERENCE_ANCHOR + key;
                    auto formatValue = value.getString().value();
                    auto formatStr = value2.getString().value();
                    substituteDefinition(formatKey, formatValue, formatStr);
                    value2.setString(formatStr);
                }
            }
        }

        auto assetStr = asset.str();
        for (auto& [key, value] : definitionsObject)
        {
            if (value.isNull())
            {
                throw std::runtime_error(fmt::format(
                    "[substituteDefinitions(asset)] Definition [{}] is null", key));
            }
            auto formatKey = syntax::REFERENCE_ANCHOR + key;
            auto formatValue = value.getString().value();
            substituteDefinition(formatKey, formatValue, assetStr);
        }

        try
        {
            asset = Json {assetStr.c_str()};
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("[substituteDefinitions(asset)] Definition substitution "
                            "yield to bad json [{}]",
                            assetStr));
        }
    }
}

} // namespace builder::internals
