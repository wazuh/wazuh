#include "definitions.hpp"

#include <algorithm>

#include "syntax.hpp"
#include <fmt/format.h>

namespace
{
/**
 * @brief Replace all occurrences of key with value in text.
 *
 * @param key The key to replace.
 * @param value The value to replace with.
 * @param text The text to replace in.
 */
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
            fmt::format("Engine definitions: Asset is expected to be an object but it "
                        "is of type \"{}\". The asset name cannot be obtained.",
                        asset.typeName()));
    }

    const std::string assetName {asset.getString("/name").value_or("")};

    if (asset.exists(DEFINITIONS_KEY))
    {
        if (!asset.isObject(DEFINITIONS_KEY))
        {
            // TODO: add getTypeName with path to Json
            throw std::runtime_error(
                fmt::format("Engine definitions: Field \"{}\" from asset \"{}\" is "
                            "expected to be an object, but it is not.",
                            DEFINITIONS_KEY,
                            assetName));
        }
        auto definitionsObject = asset.getObject(DEFINITIONS_KEY).value();
        if (!asset.erase(DEFINITIONS_KEY))
        {
            throw std::runtime_error(fmt::format(
                R"(Engine definitions: Field "{}" from asset "{}" could not be erased.)",
                DEFINITIONS_KEY,
                assetName));
        }

        // Definitions can reference other definitions, so we need to check other
        // definitions as well.
        for (auto& [key, value] : definitionsObject)
        {
            for (auto& [key2, value2] : definitionsObject)
            {
                if (key != key2)
                {
                    const auto formatKey = syntax::REFERENCE_ANCHOR + key;
                    const auto formatValue = value.getString().value();
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
                    "Engine definitions: On the asset \"{}\", the object \"{}\" contains "
                    "a key (\"{}\") with a null value, which is not allowed.",
                    assetName,
                    DEFINITIONS_KEY,
                    key));
            }
            const auto formatKey = syntax::REFERENCE_ANCHOR + key;
            const auto formatValue = value.getString().value();
            substituteDefinition(formatKey, formatValue, assetStr);
        }

        try
        {
            asset = Json {assetStr.c_str()};
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Engine definitions: On the asset \"{}\", its definition "
                            "substitution resulted in a wrong json: \"{}\".",
                            assetName,
                            assetStr));
        }
    }
}

} // namespace builder::internals
