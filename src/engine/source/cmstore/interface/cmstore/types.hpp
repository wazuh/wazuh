#ifndef _CMSTORE_ITYPES
#define _CMSTORE_ITYPES

#include <cstdint>
#include <string>
#include <string_view>

namespace cm::store
{

enum class AssetType : uint8_t
{
    UNDEFINED = 0,
    DECODER = 1,
    INTEGRATION = 2
};

constexpr std::string_view ASSET_TYPE_UNDEFINED_STR = "undefined";
constexpr std::string_view ASSET_TYPE_DECODER_STR = "decoder";
constexpr std::string_view ASSET_TYPE_INTEGRATION_STR = "integration";

constexpr AssetType assetTypeFromString(std::string_view typeStr)
{
    if (typeStr == ASSET_TYPE_DECODER_STR)
    {
        return AssetType::DECODER;
    }
    else if (typeStr == ASSET_TYPE_INTEGRATION_STR)
    {
        return AssetType::INTEGRATION;
    }
    else
    {
        return AssetType::UNDEFINED;
    }
}

constexpr std::string_view assetTypeToString(AssetType type)
{
    switch (type)
    {
        case AssetType::DECODER: return ASSET_TYPE_DECODER_STR;
        case AssetType::INTEGRATION: return ASSET_TYPE_INTEGRATION_STR;
        default: return ASSET_TYPE_UNDEFINED_STR;
    }
}

} // namespace cm::store

#endif // _CMSTORE_ITYPES
