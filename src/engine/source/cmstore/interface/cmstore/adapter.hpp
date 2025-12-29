#ifndef _CMSTORE_ICMSTORE_ADAPTER
#define _CMSTORE_ICMSTORE_ADAPTER

#include <functional>
#include <optional>
#include <string>

#include <base/json.hpp>

namespace
{

json::Json adaptDecoder(const json::Json& document)
{
    json::Json result;
    result.setObject();

    // Order: name, metadata, parent, definitions, parse|${XX}, normalize

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

    // 2. metadata
    if (document.exists("/metadata"))
    {
        auto metadataOpt = document.getJson("/metadata");
        if (metadataOpt.has_value())
        {
            result.set("/metadata", *metadataOpt);
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

    // 3. definitions
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


    // 4. parse|${XXX} (from /parse|\W+)
    {
        const auto fullDocOpt = document.getObject();
        if (!fullDocOpt.has_value())
        {
            throw std::runtime_error("Decoder document is not a valid JSON object");
        }
        for (const auto& [key, value] : *fullDocOpt)
        {
            if (key.find("parse|") == 0)
            {
                result.set(fmt::format("/{}", key), value);
                break; // Only one parse|XXX expected
            }
        }
    }

    // 5. normalize
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

    // 6. enabled
    if (document.exists("/enabled"))
    {
        auto enabledOpt = document.getJson("/enabled");
        if (enabledOpt.has_value())
        {
            result.set("/enabled", *enabledOpt);
        }
    }

    // 7. id
    if (document.exists("/id"))
    {
        auto idOpt = document.getJson("/id");
        if (idOpt.has_value())
        {
            result.set("/id", *idOpt);
        }
    }

    return result;
}
} // namespace

#endif // _CMSTORE_ICMSTORE_ADAPTER
