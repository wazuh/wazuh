#ifndef _CTI_ISTORE_ADAPTER
#define _CTI_ISTORE_ADAPTER

#include <functional>
#include <optional>
#include <string>

#include <base/json.hpp>

#include <ctistore/icmreader.hpp>

namespace
{
json::Json adaptIntegration(const json::Json& document, const std::shared_ptr<cti::store::ICMReader>& reader)
{
    json::Json result;
    result.setObject();

    // Order: name, decoders

    // 1. name (from /payload/document/title)
    if (const std::optional<std::string> titleOpt = document.getString("/title"); titleOpt.has_value())
    {
        result.setString(fmt::format("integration/{}/0", *titleOpt), "/name");
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
            const auto resolvedName = reader->resolveNameFromUUID(uuid);
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

    return result;
}
} // namespace

namespace cti::store
{

/**
 * @brief Static utility class for adapting CTI assets from storage format to consumer format.
 *
 * This class provides pure static methods to transform raw asset data returned by
 * CTIStorageDB into formats suitable for different consumers.
 *
 */
class CTIAssetAdapter
{

public:
    // Delete constructors - this is a static-only utility class
    CTIAssetAdapter() = delete;
    CTIAssetAdapter(const CTIAssetAdapter&) = delete;
    CTIAssetAdapter& operator=(const CTIAssetAdapter&) = delete;

    /**
     * @brief Adapt a raw asset document to consumer format.
     * @param rawAsset Raw asset from storage (with /name and /payload)
     * @param assetType Asset type for type-specific transformations
     * @param resolver Optional function to resolve UUIDs to names (for decoders in integrations)
     * @return Adapted asset document (just /payload section)
     * @throws std::runtime_error if raw asset is missing required sections
     */
    static json::Json
    adaptAsset(const json::Json& rawAsset, const std::string& assetType, const std::shared_ptr<ICMReader>& reader)
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
            return adaptIntegration(*documentOpt, reader);
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

    /**
     * @brief Adapt a KVDB document to consumer format.
     * @param rawKVDB Raw KVDB document from storage
     * @return Adapted KVDB content
     * @throws std::runtime_error if raw KVDB is missing required sections
     */
    static json::Json adaptKVDB(const json::Json& rawKVDB)
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

    /**
     * @brief Adapt a policy document to consumer format.
     * @param rawPolicy Raw policy document from storage
     * @return Adapted policy document
     * @throws std::runtime_error if raw policy is missing required sections
     */
    static json::Json adaptPolicy(const json::Json& rawPolicy)
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
};

} // namespace cti::store

#endif // _CTI_ISTORE_ADAPTER
