#include <ctistore/ctiassetadapter.hpp>
#include <base/logging.hpp>
#include <stdexcept>

namespace cti::store
{

namespace
{
    json::Json adaptIntegration(const json::Json& document, const UUIDResolverFn& resolver)
    {
        json::Json result;
        result.setObject();

        // Order: name, decoders

        // 1. name (from /payload/document/title)
        if (const std::optional<std::string> titleOpt = document.getString("/title"); titleOpt.has_value())
        {
            result.setString(*titleOpt, "/name");
        }

        // 2. decoders - resolve UUIDs to names if resolver provided
        if (const auto decoderArrayOpt = document.getArray("/decoders"); decoderArrayOpt.has_value())
        {
            const auto& decodersArray = *decoderArrayOpt;
            result.setArray("/decoders");

            // Change forma container
            for (const auto& element : decodersArray)
            {
                // Each element is expected to be a string UUID
                auto uuidOpt = element.getString();
                if (!uuidOpt.has_value() || uuidOpt->empty())
                {
                    throw std::runtime_error(
                        "Invalid decoder UUID in integration document, decoders must be non-empty strings");
                }
                const std::string& uuid = *uuidOpt;

                if (resolver == nullptr)
                {
                    // No resolver provided, keep UUID as-is
                    result.appendString(uuid, "/decoders");
                    continue;
                }

                const auto resolvedName = resolver(uuid, "decoder");
                result.appendString(resolvedName, "/decoders");
            }
        }

        return result;
    }

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
        if (document.exists("/definitions"))
        {
            // If is string, parse and assign
            if (auto defStrOpt = document.getString("/definitions"); defStrOpt.has_value())
            {
                try
                {
                    json::Json defJson(defStrOpt.value().c_str());
                    result.set("/definitions", defJson);
                }
                catch (const std::exception& e)
                {
                    // Not a valid JSON string, log and continue
                    throw std::runtime_error(
                        fmt::format("Decoder definitions is not valid JSON string: {}", e.what()));
                }
            }
            else if (document.isObject("/definitions"))
            {
                // Already an object, copy as-is
                // TODO: Delete this
                auto defJsonOpt = document.getJson("/definitions");
                if (defJsonOpt.has_value())
                {
                    result.set("/definitions", *defJsonOpt);
                }
            }
            else
            {
                throw std::runtime_error("Decoder definitions is neither a JSON string nor an object");
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
                    result.set(key, value);
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
                if (element.isString())
                {
                    const auto jStr = element.getString().value_or("error type");
                    result.appendJson(json::Json(jStr.c_str()), "/normalize");
                }
                else if (element.isObject())
                {
                    // TODO: Delete this
                    const auto jObjOpt = element.getJson();
                    if (jObjOpt.has_value())
                    {
                        result.appendJson(*jObjOpt, "/normalize");
                    }
                }
                else
                {
                    throw std::runtime_error("Decoder normalize array contains invalid element type, expected string or object");
                }
            }
        }

        return result;
    }
}

json::Json CTIAssetAdapter::adaptAsset(const json::Json& rawAsset,
                                       const std::string& assetType,
                                       const UUIDResolverFn& resolver)
{
    // Extract the payload section - this is the raw asset data
    auto payloadOpt = rawAsset.getJson("/payload");
    if (!payloadOpt)
    {
        throw std::runtime_error("Raw asset missing /payload section");
    }

    // Extract document section
    auto documentOpt = payloadOpt->getJson("/document");
    if (!documentOpt)
    {
        throw std::runtime_error("Payload missing /document section");
    }

    // Apply type-specific transformations
    if (assetType == "integration")
    {
        return adaptIntegration(*documentOpt, resolver);
    }
    else if (assetType == "decoder")
    {
        return adaptDecoder(*documentOpt);
    }
    else if (assetType == "policy")
    {
        // Policies don't have specific ordering requirements yet
        return *payloadOpt;
    }
    else
    {
        // Unknown type - return payload as-is
        return *payloadOpt;
    }
}

json::Json CTIAssetAdapter::adaptKVDB(const json::Json& rawKVDB)
{

    if (!rawKVDB.exists("/payload/document/content"))
    {
        throw std::runtime_error("Raw KVDB missing /payload/document/content section");
    }
    if (!rawKVDB.isObject("/payload/document/content"))
    {
        throw std::runtime_error("/payload/document/content is not a JSON object");
    }

    return rawKVDB.getJson("/payload/document/content").value_or(json::Json());
}

json::Json CTIAssetAdapter::adaptPolicy(const json::Json& rawPolicy)
{
    auto payloadOpt = rawPolicy.getJson("/payload");
    if (!payloadOpt)
    {
        throw std::runtime_error("Raw policy missing /payload section");
    }

    json::Json result;
    result.setObject();

    // 1. name (from /payload/title or /payload/document/title)
    if (payloadOpt->exists("/document/title"))
    {
        auto titleOpt = payloadOpt->getString("/document/title");
        if (titleOpt.has_value())
        {
            result.setString(*titleOpt, "/name");
        }
    }
    // Fallback to /payload/title (flat format)
    else if (payloadOpt->exists("/title"))
    {
        auto titleOpt = payloadOpt->getString("/title");
        if (titleOpt.has_value())
        {
            result.setString(*titleOpt, "/name");
        }
    }
    return *payloadOpt;
}

} // namespace cti::store
