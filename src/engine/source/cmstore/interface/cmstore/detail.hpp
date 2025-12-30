#ifndef _CMSTORE_ICMSTORE_DETAIL
#define _CMSTORE_ICMSTORE_DETAIL

#include <algorithm>
#include <cctype>
#include <functional>
#include <optional>
#include <string>
#include <unordered_set>

#include <base/json.hpp>

namespace cm::store::detail
{

inline std::optional<std::string> findDuplicateUUID(const std::vector<std::string>& uuids, bool caseInsensitive = true)
{
    std::unordered_set<std::string> seen;
    seen.reserve(uuids.size());

    for (const auto& original : uuids)
    {
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
            return original;
        }
    }

    return std::nullopt;
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
} // namespace cm::store::detail

#endif // _CMSTORE_ICMSTORE_DETAIL
