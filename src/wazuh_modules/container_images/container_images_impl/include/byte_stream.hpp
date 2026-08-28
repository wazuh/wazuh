/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BYTE_STREAM_HPP
#define _BYTE_STREAM_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace containerimages
{
    /// @brief A sequential source of bytes.
    ///
    /// Everything that reads image data goes through this interface, so the layer reader
    /// consumes bytes without knowing where they come from: a file on disk today, a
    /// member of a saved archive, and a remote blob once registries are supported.
    class IByteStream
    {
        public:
            virtual ~IByteStream() = default;

            /// @brief Read up to @p size bytes into @p buffer.
            /// @return Bytes read; 0 once the stream is exhausted.
            virtual std::size_t read(char* buffer, std::size_t size) = 0;
    };

    /// @brief Read exactly @p size bytes, unless the stream ends first.
    /// @return Bytes actually read, which is lower than @p size only at end of stream.
    std::size_t readExact(IByteStream& stream, char* buffer, std::size_t size);

    /// @brief Discard @p size bytes from the stream.
    /// @return True if every requested byte was available.
    bool skipBytes(IByteStream& stream, std::uint64_t size);

    /// @brief Reads a regular file from disk.
    class FileByteStream final : public IByteStream
    {
        public:
            explicit FileByteStream(const std::filesystem::path& path);

            /// @brief True when the file was opened.
            bool isOpen() const;

            std::size_t read(char* buffer, std::size_t size) override;

        private:
            std::ifstream m_file;
    };

    /// @brief Reads from a buffer already held in memory.
    class MemoryByteStream final : public IByteStream
    {
        public:
            explicit MemoryByteStream(std::string content);

            std::size_t read(char* buffer, std::size_t size) override;

        private:
            std::string m_content;
            std::size_t m_offset {0};
    };

    /// @brief Exposes at most @p limit bytes of an underlying stream.
    ///
    /// Used to hand a tar entry's content to a caller that must not be able to read past
    /// the entry, and to know afterwards how much of it was consumed.
    class BoundedByteStream final : public IByteStream
    {
        public:
            BoundedByteStream(IByteStream& source, std::uint64_t limit);

            std::size_t read(char* buffer, std::size_t size) override;

            /// @brief Bytes not yet consumed out of the limit.
            std::uint64_t remaining() const;

        private:
            IByteStream& m_source;
            std::uint64_t m_remaining;
    };

    /// @brief How a layer blob is compressed, decided from its first bytes.
    ///
    /// The media type in the image manifest names the same thing, but it is metadata the
    /// image itself supplies, so the bytes are the authority here. A blob with none of
    /// the known signatures is read as a plain tar, which is what an uncompressed layer
    /// is.
    enum class LayerCompression
    {
        None,  ///< No signature matched: read as a plain tar.
        Gzip,  ///< Decompressed.
        Zstd,  ///< Decompressed.
        Xz,    ///< Recognized, not supported yet.
        Bzip2, ///< Recognized, not supported yet.
        Lz4,   ///< Recognized, not supported yet.
    };

    /// @brief Name of a compression, for the log.
    std::string compressionName(LayerCompression compression);

    /// @brief True when the stream can decompress this one.
    bool isCompressionSupported(LayerCompression compression);

    /// @brief Decompresses a layer blob, or passes the bytes through unchanged.
    ///
    /// Handles the compressions the OCI image specification defines for a layer: gzip,
    /// zstd, and none. A blob compressed with anything else that can be recognized from
    /// its signature yields no bytes, so the caller can report it rather than read the
    /// compressed bytes as if they were tar data and call the layer malformed.
    class LayerByteStream final : public IByteStream
    {
        public:
            explicit LayerByteStream(IByteStream& source);
            ~LayerByteStream() override;

            LayerByteStream(const LayerByteStream&) = delete;
            LayerByteStream& operator=(const LayerByteStream&) = delete;

            std::size_t read(char* buffer, std::size_t size) override;

            /// @brief The compression this blob turned out to use.
            ///
            /// Reads the signature on the first call, so it is usable before any content
            /// has been asked for.
            LayerCompression compression();

        private:
            /// @brief Read the signature and set up the decompressor it names.
            void start();

            /// @brief Copy out of the signature bytes kept back by start().
            std::size_t drainPending(char* buffer, std::size_t size);

            /// @brief Refill the compressed input buffer from the source.
            bool refill();

            /// @brief Decompress into @p buffer with zlib.
            std::size_t readInflate(char* buffer, std::size_t size);

            /// @brief Decompress into @p buffer with zstd.
            std::size_t readZstd(char* buffer, std::size_t size);

            static constexpr std::size_t BUFFER_SIZE {64 * 1024};

            IByteStream& m_source;
            std::string m_pending;                  ///< Signature bytes read by start(), still owed to the caller.
            std::size_t m_pendingOffset {0};
            std::vector<char> m_input {};           ///< Compressed bytes pulled from the source.
            std::size_t m_inputSize {0};
            std::size_t m_inputOffset {0};
            bool m_started {false};
            bool m_finished {false};
            LayerCompression m_compression {LayerCompression::None};
            /// Owns the zlib stream. void* keeps <zlib.h> out of this header, so every
            /// translation unit that reads a stream does not need the zlib include path.
            std::unique_ptr<void, void (*)(void*)> m_inflate;
            /// Owns the zstd stream, kept opaque for the same reason.
            std::unique_ptr<void, void (*)(void*)> m_zstd;
    };
} // namespace containerimages

#endif // _BYTE_STREAM_HPP
