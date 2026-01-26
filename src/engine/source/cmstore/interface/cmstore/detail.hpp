#ifndef _CMSTORE_ICMSTORE_DETAIL
#define _CMSTORE_ICMSTORE_DETAIL

#include <algorithm>
#include <cctype>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>

#include <base/json.hpp>
#include <base/utils/generator.hpp>

#include <cmstore/detail.hpp>

namespace cm::store::detail
{

inline void
findDuplicateOrInvalidUUID(const std::vector<std::string>& uuids, const std::string& type, bool caseInsensitive = true)
{
    std::unordered_set<std::string> seen;
    seen.reserve(uuids.size());

    for (const auto& original : uuids)
    {
        if (!base::utils::generators::isValidUUIDv4(original))
        {
            throw std::runtime_error(type + " UUID is not a valid UUIDv4: " + original);
        }

        std::string key = original;
        if (caseInsensitive)
        {
            std::transform(key.begin(),
                           key.end(),
                           key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        }

        if (!seen.insert(key).second)
        {
            throw std::runtime_error("Duplicate " + type + " UUID: " + original);
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
        auto nameOpt = document.getString("/name");
        if (nameOpt.has_value())
        {
            result.setString(*nameOpt, "/name");
        }
        else
        {
            throw std::runtime_error("Decoder document /name is not a string");
        }
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

    // 4. normalize
    if (const auto normalizeOpt = document.getArray("/normalize"); normalizeOpt.has_value())
    {
        result.setArray("/normalize");
        const auto& normalizeArray = *normalizeOpt;
        for (const auto& element : normalizeArray)
        {
            if (element.isObject())
            {
                json::Json orderedObj;
                orderedObj.setObject();

                // Order keys check, parse|.*, map
                if (element.exists("/check"))
                {
                    auto checkOpt = element.getJson("/check");
                    if (checkOpt.has_value())
                    {
                        orderedObj.set("/check", *checkOpt);
                    }
                }

                {
                    const auto fullElemOpt = element.getObject();
                    if (!fullElemOpt.has_value())
                    {
                        throw std::runtime_error("Decoder normalize array contains invalid element, not an object");
                    }
                    for (const auto& [key, value] : *fullElemOpt)
                    {
                        if (key.find("parse|") == 0)
                        {
                            orderedObj.set(fmt::format("/{}", key), value);
                            break; // Only one parse|XXX expected
                        }
                    }
                }

                if (element.exists("/map"))
                {
                    auto mapOpt = element.getJson("/map");
                    if (mapOpt.has_value())
                    {
                        orderedObj.set("/map", *mapOpt);
                    }
                }

                result.appendJson(orderedObj, "/normalize");
            }
            else
            {
                throw std::runtime_error(
                    "Decoder normalize array contains invalid element type, expected string or object");
            }
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
        auto idOpt = document.getString("/id");
        if (!idOpt.has_value())
        {
            throw std::runtime_error("Decoder document /id is not a string");
        }
        result.setString(*idOpt, "/id");
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
        auto nameOpt = document.getString("/name");
        if (nameOpt.has_value())
        {
            result.setString(*nameOpt, "/name");
        }
        else
        {
            throw std::runtime_error("Filter document /name is not a string");
        }
    }

    // 2. type
    auto typeOpt = document.getString("/type");
    if (!typeOpt.has_value())
    {
        throw std::runtime_error("Filter document /type is not a string or does not exist");
    }
    result.setString(*typeOpt, "/type");

    // 3. Copy /check
    if (document.exists("/check"))
    {
        auto checkOpt = document.getJson("/check");
        if (checkOpt.has_value())
        {
            result.set("/check", *checkOpt);
        }
    }

    // 4. enabled
    auto enabledOpt = document.getBool("/enabled");
    if (!enabledOpt.has_value())
    {
        throw std::runtime_error("Filter document /enabled is not a boolean or does not exist");
    }
    result.setBool(*enabledOpt, "/enabled");

    // 5. id
    if (document.exists("/id"))
    {
        auto idOpt = document.getString("/id");
        if (!idOpt.has_value())
        {
            throw std::runtime_error("Filter document /id is not a string");
        }
        result.setString(*idOpt, "/id");
    }
    return result;
}

inline json::Json adaptOutput(const json::Json& document)
{
    json::Json result;
    result.setObject();

    // Order: name, outputs (with first_of, check, then)

    // 1. name (from /name)
    if (document.exists("/name"))
    {
        auto nameOpt = document.getString("/name");
        if (nameOpt.has_value())
        {
            result.setString(*nameOpt, "/name");
        }
        else
        {
            throw std::runtime_error("Output document /name is not a string");
        }
    }

    // 2. outputs array (contains the first_of logic with check and then blocks)
    if (const auto outputsArrayOpt = document.getArray("/outputs"); outputsArrayOpt.has_value())
    {
        result.setArray("/outputs");
        const auto& outputsArray = *outputsArrayOpt;

        for (const auto& outputElement : outputsArray)
        {
            if (outputElement.isObject())
            {
                // Check if it has first_of array
                if (outputElement.exists("/first_of"))
                {
                    const auto firstOfArrayOpt = outputElement.getArray("/first_of");
                    if (firstOfArrayOpt.has_value())
                    {
                        json::Json orderedOutput;
                        orderedOutput.setObject();
                        orderedOutput.setArray("/first_of");
                        const auto& firstOfArray = *firstOfArrayOpt;

                        for (const auto& firstOfElement : firstOfArray)
                        {
                            if (firstOfElement.isObject())
                            {
                                json::Json orderedFirstOf;
                                orderedFirstOf.setObject();

                                // Order: check, then
                                if (firstOfElement.exists("/check"))
                                {
                                    auto checkOpt = firstOfElement.getJson("/check");
                                    if (checkOpt.has_value())
                                    {
                                        orderedFirstOf.set("/check", *checkOpt);
                                    }
                                }

                                if (firstOfElement.exists("/then"))
                                {
                                    auto thenOpt = firstOfElement.getJson("/then");
                                    if (thenOpt.has_value())
                                    {
                                        orderedFirstOf.set("/then", *thenOpt);
                                    }
                                }

                                orderedOutput.appendJson(orderedFirstOf, "/first_of");
                            }
                            else
                            {
                                throw std::runtime_error(
                                    "Output first_of array contains invalid element type, expected object");
                            }
                        }

                        result.appendJson(orderedOutput, "/outputs");
                    }
                }
                else
                {
                    // If no first_of, copy the element as-is
                    result.appendJson(outputElement, "/outputs");
                }
            }
            else
            {
                throw std::runtime_error("Output outputs array contains invalid element type, expected object");
            }
        }
    }

    // 3. enabled
    auto enabledOpt = document.getBool("/enabled");
    if (!enabledOpt.has_value())
    {
        throw std::runtime_error("Output document /enabled is not a boolean or does not exist");
    }
    result.setBool(*enabledOpt, "/enabled");

    // 5. id (optional)
    if (document.exists("/id"))
    {
        auto idOpt = document.getString("/id");
        if (!idOpt.has_value())
        {
            throw std::runtime_error("Output document /id is not a string");
        }
        result.setString(*idOpt, "/id");
    }

    return result;
}

} // namespace cm::store::detail

#endif // _CMSTORE_ICMSTORE_DETAIL
