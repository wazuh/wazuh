#ifndef _CTI_STORE_CTI_ASSET_ADAPTER_HPP
#define _CTI_STORE_CTI_ASSET_ADAPTER_HPP

#include <base/json.hpp>
#include <string>
#include <functional>
#include <optional>

namespace cti::store
{

/**
 * @brief Function type for resolving UUIDs to names
 * @param uuid The UUID to resolve
 * @param assetType The type of asset ("decoder", "kvdb", etc.)
 * @return The resolved name, or std::nullopt if resolution fails
 */
using UUIDResolver = std::function<std::optional<std::string>(const std::string& uuid, const std::string& assetType)>;

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
    static json::Json adaptAsset(const json::Json& rawAsset,
                                  const std::string& assetType,
                                  const UUIDResolver& resolver = nullptr);

    /**
     * @brief Adapt a KVDB document to consumer format.
     * @param rawKVDB Raw KVDB document from storage
     * @return Adapted KVDB content
     * @throws std::runtime_error if raw KVDB is missing required sections
     */
    static json::Json adaptKVDB(const json::Json& rawKVDB);

    /**
     * @brief Adapt a policy document to consumer format.
     * @param rawPolicy Raw policy document from storage
     * @return Adapted policy document
     * @throws std::runtime_error if raw policy is missing required sections
     */
    static json::Json adaptPolicy(const json::Json& rawPolicy);
};

} // namespace cti::store

#endif // _CTI_STORE_CTI_ASSET_ADAPTER_HPP
