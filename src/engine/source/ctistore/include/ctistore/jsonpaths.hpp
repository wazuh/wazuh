#ifndef CTI_STORE_JSON_PATHS_HPP
#define CTI_STORE_JSON_PATHS_HPP

#include <string_view>

namespace cti::store
{
namespace jsonPath
{
// Core message level
inline constexpr std::string_view PATHS {"/paths"};
inline constexpr std::string_view TYPE {"/type"};
inline constexpr std::string_view OFFSET {"/offset"};
inline constexpr std::string_view DATA {"/data"};
inline constexpr std::string_view FILE_METADATA_HASH {"/fileMetadata/hash"};

// Common entry/document identifiers
inline constexpr std::string_view NAME {"/name"};
inline constexpr std::string_view RESOURCE {"/resource"};
inline constexpr std::string_view OPERATIONS {"/operations"};

// Payload / document structure
inline constexpr std::string_view PAYLOAD {"/payload"};
inline constexpr std::string_view PAYLOAD_TYPE {"/payload/type"};
inline constexpr std::string_view PAYLOAD_TITLE {"/payload/title"};
inline constexpr std::string_view PAYLOAD_INTEGRATION_ID {"/payload/integration_id"};
inline constexpr std::string_view INTEGRATION_ID {"/integration_id"};
inline constexpr std::string_view PAYLOAD_DOCUMENT {"/payload/document"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_TITLE {"/payload/document/title"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_NAME {"/payload/document/name"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_METADATA_MODULE {"/payload/document/metadata/module"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_DECODERS {"/payload/document/decoders"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_KVDBS {"/payload/document/kvdbs"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_CONTENT {"/payload/document/content"};
inline constexpr std::string_view PAYLOAD_INTEGRATIONS {"/payload/integrations"};
inline constexpr std::string_view PAYLOAD_DOCUMENT_INTEGRATIONS {"/payload/document/integrations"};

// Unwrapped (post-processed) document paths
inline constexpr std::string_view UNWRAPPED_DOCUMENT_TITLE {"/document/title"};
inline constexpr std::string_view UNWRAPPED_DOCUMENT_NAME {"/document/name"};
inline constexpr std::string_view UNWRAPPED_DOCUMENT_CONTENT {"/document/content"};

} // namespace jsonPath
} // namespace cti::store

#endif // CTI_STORE_JSON_PATHS_HPP
