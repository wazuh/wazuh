#pragma once

#include <cstddef>

namespace wazuh::container_baseline {

/// @brief Data classes an image source file feeds.
inline constexpr unsigned IMAGE_SOURCE_PACKAGES = 1u << 0;
inline constexpr unsigned IMAGE_SOURCE_USERS    = 1u << 1;
inline constexpr unsigned IMAGE_SOURCE_OS       = 1u << 2;

/// @brief How a source is read, and so how it is fingerprinted.
enum class ImageSourceKind
{
    file,      ///< Read as a whole.
    directory, ///< The files directly inside it are read.
    wal,       ///< A database's write-ahead log, read with it when not empty.
};

/// @brief A file, inside the container's rootfs, that packages, users, groups
/// or the OS record are read from.
struct ImageSourceFile
{
    const char*     path;    ///< Absolute in-container path.
    unsigned        classes; ///< IMAGE_SOURCE_* bits.
    ImageSourceKind kind;
};

/// @brief Every file the user, OS and package scanners read. The image-content
/// cache fingerprints exactly these, and a write to any of them is what makes a
/// container's inventory stale; a path read but missing here would let a
/// modified file serve stale cached rows.
[[nodiscard]] const ImageSourceFile* ImageSourceFiles(std::size_t& count);

} // namespace wazuh::container_baseline
