#include <ctistore/ctiassetadapter.hpp>
#include <base/logging.hpp>
#include <stdexcept>

namespace cti::store
{

namespace
{
    json::Json adaptIntegration(const json::Json& document, const UUIDResolver& resolver)
    {
        json::Json result;
        result.setObject();

        // Order: name, decoders

        // 1. name (from /payload/document/title)
        if (document.exists("/title"))
        {
            auto titleOpt = document.getString("/title");
            if (titleOpt.has_value())
            {
                result.setString(*titleOpt, "/name");
            }
        }

        // 2. decoders - resolve UUIDs to names if resolver provided
        if (document.exists("/decoders"))
        {
            auto decodersOpt = document.getJson("/decoders");
            if (decodersOpt.has_value() && decodersOpt->isArray())
            {
                auto decodersArray = decodersOpt->getArray();
                if (decodersArray.has_value())
                {
                    json::Json resolvedDecoders;
                    resolvedDecoders.setArray();

                    for (size_t i = 0; i < decodersArray->size(); ++i)
                    {
                        json::Json element(decodersArray->at(i));
                        auto uuidOpt = element.getString();

                        if (uuidOpt.has_value())
                        {
                            const std::string& uuid = *uuidOpt;

                            // Try to resolve UUID to name if resolver provided
                            if (resolver)
                            {
                                auto resolvedName = resolver(uuid, "decoder");
                                if (resolvedName.has_value())
                                {
                                    resolvedDecoders.appendString(*resolvedName);
                                }
                                else
                                {
                                    // Resolution failed, keep UUID
                                    LOG_WARNING("Failed to resolve decoder UUID: {}", uuid);
                                    resolvedDecoders.appendString(uuid);
                                }
                            }
                            else
                            {
                                // No resolver, keep UUID as-is
                                resolvedDecoders.appendString(uuid);
                            }
                        }
                    }

                    result.set("/decoders", resolvedDecoders);
                }
            }
        }

        return result;
    }

    json::Json adaptDecoder(const json::Json& document)
    {
        json::Json result;
        result.setObject();

        // Order: name, metadata, definitions, parse|event.original, normalize

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

        // 3. definitions
        if (document.exists("/definitions"))
        {
            auto defsOpt = document.getJson("/definitions");
            if (defsOpt.has_value())
            {
                result.set("/definitions", *defsOpt);
            }
        }

        // 4. parse|event.original (from /parse/event.original)
        if (document.exists("/parse"))
        {
            auto parseOpt = document.getJson("/parse");
            if (parseOpt.has_value() && parseOpt->exists("/event.original"))
            {
                auto eventOrigOpt = parseOpt->getJson("/event.original");
                if (eventOrigOpt.has_value())
                {
                    result.set("/parse|event.original", *eventOrigOpt);
                }
            }
        }

        // 5. normalize
        if (document.exists("/normalize"))
        {
            auto normalizeOpt = document.getJson("/normalize");
            if (normalizeOpt.has_value())
            {
                result.set("/normalize", *normalizeOpt);
            }
        }

        return result;
    }
}

json::Json CTIAssetAdapter::adaptAsset(const json::Json& rawAsset,
                                       const std::string& assetType,
                                       const UUIDResolver& resolver)
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
    auto payloadOpt = rawKVDB.getJson("/payload");
    if (!payloadOpt)
    {
        throw std::runtime_error("Raw KVDB missing /payload section");
    }

    auto documentOpt = payloadOpt->getJson("/document");
    if (!documentOpt)
    {
        throw std::runtime_error("KVDB payload missing /document section");
    }

    json::Json result;
    result.setObject();

    // 1. name (from /payload/document/title)
    if (documentOpt->exists("/title"))
    {
        auto titleOpt = documentOpt->getString("/title");
        if (titleOpt.has_value())
        {
            result.setString(*titleOpt, "/name");
        }
    }

    // 2. content (from /payload/document/content)
    if (documentOpt->exists("/content"))
    {
        auto contentOpt = documentOpt->getJson("/content");
        if (contentOpt.has_value())
        {
            result.set("/content", *contentOpt);
        }
    }

    return result;
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
