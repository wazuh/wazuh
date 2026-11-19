// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _CMSTORE_ICMSTORE_DETAIL
#define _CMSTORE_ICMSTORE_DETAIL

#include <algorithm>
#include <cctype>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>

#include <base/json.hpp>
#include <base/name.hpp>
#include <base/utils/generator.hpp>

namespace
{
/**
 * @brief Check asset name validity according to its type.
 *
 * TODO: This function will be remove when support traceable for any name.
 * @param name Name to check
 * @param prefix Expected prefix for the asset type
 * @throw std::logic_error if the type is not supported for name validation
 */
inline void checkAssetName(const std::string& name, std::string_view prefix)
{
    const auto assetName = [&]() -> base::Name
    {
        try
        {
            return base::Name {name};
        }
        catch (const std::runtime_error& e)
        {
            throw std::runtime_error(fmt::format("Invalid {} name '{}': {}", prefix, name, e.what()));
        }
    }();

    if (assetName.parts().size() != 3)
    {
        throw std::runtime_error(
            fmt::format("Asset name '{}' must have exactly 3 parts '{}/<name>/<version>'", name, prefix));
    }

    if (assetName.parts()[0] != prefix)
    {
        throw std::runtime_error(fmt::format("Asset name '{}' must start with prefix '{}'", name, prefix));
    }
}

} // namespace

namespace cm::store::detail
{

/**
 * @brief Checks a list of resource identifiers.
 *
 * Every identifier must satisfy base::utils::generators::isValidResourceId() and the list must
 * not contain duplicates. Identifiers are opaque and compared byte by byte: no case folding or
 * any other normalization is applied, so two identifiers that only differ in case are distinct.
 *
 * @param uuids Identifiers to check
 * @param type Resource type used in the error messages (e.g. "Decoder")
 * @throw std::runtime_error if an identifier is not valid or appears more than once
 */
inline void findDuplicateOrInvalidUUID(const std::vector<std::string>& uuids, const std::string& type)
{
    std::unordered_set<std::string> seen;
    seen.reserve(uuids.size());

    for (const auto& uuid : uuids)
    {
        if (!base::utils::generators::isValidResourceId(uuid))
        {
            throw std::runtime_error(
                fmt::format("{} UUID is not a valid identifier: {}", type, base::utils::generators::RESOURCE_ID_RULES));
        }

        if (!seen.insert(uuid).second)
        {
            throw std::runtime_error("Duplicate " + type + " UUID: " + uuid);
        }
    }
}

inline json::Json adaptDecoder(const json::Json& document)
{
    json::Json result;
    result.setObject();

    // Order: name, parent, definitions, parse|${XX}, normalize

    // 1. name (from /payload/document/name)
    // TODO: In the future this will be from /payload/document/metadata/title
    if (document.exists("/name"))
    {
        std::string name;
        if (document.getString(name, "/name") == json::RetGet::Success)
        {
            result.setString(name, "/name");
        }
        else
        {
            throw std::runtime_error("Decoder document /name is not a string");
        }

        checkAssetName(name, "decoder");
    }

    // parents
    if (document.exists("/parents"))
    {
        auto defsOpt = document.getJson("/parents");
        if (defsOpt.has_value())
        {
            result.set("/parents", *defsOpt);
        }
    }

    // 2. definitions
    if (auto defJsonOpt = document.getJson("/definitions"); defJsonOpt.has_value())
    {
        result.set("/definitions", *defJsonOpt);
    }

    // Copy /check
    if (document.exists("/check"))
    {
        auto checkOpt = document.getJson("/check");
        if (checkOpt.has_value())
        {
            result.set("/check", *checkOpt);
        }
    }

    // 3. parse|${XXX} (from /parse|\W+)
    {
        const auto fullDocOpt = document.getObject();
        if (!fullDocOpt.has_value())
        {
            throw std::runtime_error("Decoder document is not a valid JSON object");
        }

        size_t parseKeyCount = 0;
        std::string parseKey;

        for (const auto& [key, value] : *fullDocOpt)
        {
            if (key.find("parse|") == 0)
            {
                ++parseKeyCount;
                if (parseKeyCount == 1)
                {
                    parseKey = key;
                    result.set(fmt::format("/{}", key), value);
                }
            }
        }

        if (parseKeyCount > 1)
        {
            throw std::runtime_error(
                fmt::format("Decoder document contains multiple parse| keys ({}). Only one is allowed", parseKeyCount));
        }
    }

    // 4. normalize: each block is copied as written. The key order and every key (a repeated `parse|`, an unknown
    // sub-block) reach the builder unchanged, which enforces the block layout (check, parse|<field>, map; at most one
    // parse) and fails the build on a violation.
    if (const auto normalizeOpt = document.getArray("/normalize"); normalizeOpt.has_value())
    {
        result.setArray("/normalize");
        for (const auto& element : *normalizeOpt)
        {
            if (!element.isObject())
            {
                throw std::runtime_error("Decoder normalize array contains invalid element type, expected object");
            }
            result.appendJson(element, "/normalize");
        }
    }

    // 5. enabled
    auto enabledOpt = document.getBool("/enabled");
    if (!enabledOpt.has_value())
    {
        throw std::runtime_error("Decoder document /enabled is not a boolean or does not exist");
    }
    result.setBool(*enabledOpt, "/enabled");

    // 6. id
    if (document.exists("/id"))
    {
        std::string id;
        if (document.getString(id, "/id") != json::RetGet::Success)
        {
            throw std::runtime_error("Decoder document /id is not a string");
        }
        result.setString(id, "/id");
    }
    return result;
}

inline json::Json adaptFilter(const json::Json& document)
{
    json::Json result;
    result.setObject();

    // Order: name, check, type

    // 1. name (from /payload/document/name)
    // TODO: In the future this will be from /payload/document/metadata/title
    if (document.exists("/name"))
    {
        std::string name;
        if (document.getString(name, "/name") == json::RetGet::Success)
        {
            result.setString(name, "/name");
        }
        else
        {
            throw std::runtime_error("Filter document /name is not a string");
        }
        checkAssetName(name, "filter");
    }

    // 2. parents
    if (document.exists("/parents"))
    {
        auto defsOpt = document.getJson("/parents");
        if (defsOpt.has_value())
        {
            result.set("/parents", *defsOpt);
        }
    }

    // 3. definitions
    if (auto defJsonOpt = document.getJson("/definitions"); defJsonOpt.has_value())
    {
        result.set("/definitions", *defJsonOpt);
    }

    // 4. type
    std::string type;
    if (document.getString(type, "/type") != json::RetGet::Success)
    {
        throw std::runtime_error("Filter document /type is not a string or does not exist");
    }
    result.setString(type, "/type");

    // 5. Copy /check
    if (document.exists("/check"))
    {
        auto checkOpt = document.getJson("/check");
        if (checkOpt.has_value())
        {
            result.set("/check", *checkOpt);
        }
    }

    // 6. enabled
    auto enabledOpt = document.getBool("/enabled");
    if (!enabledOpt.has_value())
    {
        throw std::runtime_error("Filter document /enabled is not a boolean or does not exist");
    }
    result.setBool(*enabledOpt, "/enabled");

    // 7. id
    if (document.exists("/id"))
    {
        std::string id;
        if (document.getString(id, "/id") != json::RetGet::Success)
        {
            throw std::runtime_error("Filter document /id is not a string");
        }
        result.setString(id, "/id");
    }
    return result;
}

inline json::Json adaptOutput(const json::Json& document)
{
    json::Json result;
    result.setObject();

    // Order: name, parents, definitions, outputs, enabled, id

    // 1. name (from /name)
    if (document.exists("/name"))
    {
        std::string name;
        if (document.getString(name, "/name") == json::RetGet::Success)
        {
            result.setString(name, "/name");
        }
        else
        {
            throw std::runtime_error("Output document /name is not a string");
        }
        checkAssetName(name, "output");
    }

    // 2. parents
    if (document.exists("/parents"))
    {
        auto defsOpt = document.getJson("/parents");
        if (defsOpt.has_value())
        {
            result.set("/parents", *defsOpt);
        }
    }

    // 3. definitions
    if (auto defJsonOpt = document.getJson("/definitions"); defJsonOpt.has_value())
    {
        result.set("/definitions", *defJsonOpt);
    }

    // 4. outputs array: each element is copied as written. The key order of a first_of branch reaches the builder
    // unchanged, which requires exactly `check` then `then` and fails the build otherwise.
    if (const auto outputsArrayOpt = document.getArray("/outputs"); outputsArrayOpt.has_value())
    {
        result.setArray("/outputs");
        for (const auto& outputElement : *outputsArrayOpt)
        {
            if (!outputElement.isObject())
            {
                throw std::runtime_error("Output outputs array contains invalid element type, expected object");
            }

            if (const auto firstOfArrayOpt = outputElement.getArray("/first_of"); firstOfArrayOpt.has_value())
            {
                for (const auto& firstOfElement : *firstOfArrayOpt)
                {
                    if (!firstOfElement.isObject())
                    {
                        throw std::runtime_error(
                            "Output first_of array contains invalid element type, expected object");
                    }
                }
            }

            result.appendJson(outputElement, "/outputs");
        }
    }

    // 5. enabled
    auto enabledOpt = document.getBool("/enabled");
    if (!enabledOpt.has_value())
    {
        throw std::runtime_error("Output document /enabled is not a boolean or does not exist");
    }
    result.setBool(*enabledOpt, "/enabled");

    // 6. id (optional)
    if (document.exists("/id"))
    {
        std::string id;
        if (document.getString(id, "/id") != json::RetGet::Success)
        {
            throw std::runtime_error("Output document /id is not a string");
        }
        result.setString(id, "/id");
    }

    return result;
}

} // namespace cm::store::detail

#endif // _CMSTORE_ICMSTORE_DETAIL
