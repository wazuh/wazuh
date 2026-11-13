/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "byte_stream.hpp"

#include <zlib.h>
#include <zstd.h>

#include <algorithm>
#include <string_view>
#include <utility>

namespace
{
    /// @brief windowBits value that makes inflate() accept a gzip header.
    constexpr int GZIP_WINDOW_BITS {15 + 32};

    /// @brief Bytes read before the compression is decided. Long enough for the longest
    ///        signature below, and handed back to the decompressor or to the caller.
    constexpr std::size_t SIGNATURE_SIZE {6};

    /// @brief A compression and the bytes a blob using it starts with.
    struct Signature
    {
        containerimages::LayerCompression compression;
        std::string_view magic;
    };

    /// @brief The signatures worth recognizing, longest first so no prefix hides another.
    ///
    /// gzip and zstd are the two compressions the OCI image specification defines for a
    /// layer. The rest cannot appear in a conformant image, but they are cheap to name,
    /// and naming them is what turns "this layer is malformed" into "this layer uses a
    /// compression that is not supported yet".
    constexpr std::array<Signature, 5> SIGNATURES
    {{
        {containerimages::LayerCompression::Xz, std::string_view {"\xfd\x37\x7a\x58\x5a\x00", 6}},
        {containerimages::LayerCompression::Zstd, std::string_view {"\x28\xb5\x2f\xfd", 4}},
        {containerimages::LayerCompression::Lz4, std::string_view {"\x04\x22\x4d\x18", 4}},
        {containerimages::LayerCompression::Bzip2, std::string_view {"\x42\x5a\x68", 3}},
        {containerimages::LayerCompression::Gzip, std::string_view {"\x1f\x8b", 2}},
    }};

    /// @brief The compression @p header starts with, or None when none matches.
    containerimages::LayerCompression detectCompression(const std::string& header)
    {
        for (const auto& signature : SIGNATURES)
        {
            if (header.size() >= signature.magic.size() &&
                    header.compare(0, signature.magic.size(), signature.magic) == 0)
            {
                return signature.compression;
            }
        }

        return containerimages::LayerCompression::None;
    }

    void destroyInflateStream(void* handle)
    {
        auto* stream {static_cast<z_stream*>(handle)};

        if (stream)
        {
            inflateEnd(stream);
            delete stream;
        }
    }

    void destroyZstdStream(void* handle)
    {
        if (handle)
        {
            ZSTD_freeDStream(static_cast<ZSTD_DStream*>(handle));
        }
    }
} // namespace

namespace containerimages
{
    std::size_t readExact(IByteStream& stream, char* buffer, std::size_t size)
    {
        std::size_t total {0};

        while (total < size)
        {
            const auto got {stream.read(buffer + total, size - total)};

            if (got == 0)
            {
                break;
            }

            total += got;
        }

        return total;
    }

    bool skipBytes(IByteStream& stream, std::uint64_t size)
    {
        std::array<char, 8192> scratch {};

        while (size > 0)
        {
            const auto chunk {static_cast<std::size_t>(std::min<std::uint64_t>(size, scratch.size()))};
            const auto got {readExact(stream, scratch.data(), chunk)};

            if (got != chunk)
            {
                return false;
            }

            size -= chunk;
        }

        return true;
    }

    FileByteStream::FileByteStream(const std::filesystem::path& path)
        : m_file {path, std::ios::binary}
    {
    }

    bool FileByteStream::isOpen() const
    {
        return m_file.is_open();
    }

    std::size_t FileByteStream::read(char* buffer, std::size_t size)
    {
        if (!m_file.is_open() || size == 0)
        {
            return 0;
        }

        m_file.read(buffer, static_cast<std::streamsize>(size));
        return static_cast<std::size_t>(m_file.gcount());
    }

    MemoryByteStream::MemoryByteStream(std::string content)
        : m_content {std::move(content)}
    {
    }

    std::size_t MemoryByteStream::read(char* buffer, std::size_t size)
    {
        const auto available {m_content.size() - m_offset};
        const auto count {std::min(available, size)};

        if (count > 0)
        {
            std::copy_n(m_content.data() + m_offset, count, buffer);
            m_offset += count;
        }

        return count;
    }

    BoundedByteStream::BoundedByteStream(IByteStream& source, std::uint64_t limit)
        : m_source {source}
        , m_remaining {limit}
    {
    }

    std::size_t BoundedByteStream::read(char* buffer, std::size_t size)
    {
        const auto allowed {static_cast<std::size_t>(std::min<std::uint64_t>(m_remaining, size))};

        if (allowed == 0)
        {
            return 0;
        }

        const auto got {m_source.read(buffer, allowed)};
        m_remaining -= got;
        return got;
    }

    std::uint64_t BoundedByteStream::remaining() const
    {
        return m_remaining;
    }

    std::string compressionName(const LayerCompression compression)
    {
        switch (compression)
        {
            case LayerCompression::Gzip: return "gzip";

            case LayerCompression::Zstd: return "zstd";

            case LayerCompression::Xz: return "xz";

            case LayerCompression::Bzip2: return "bzip2";

            case LayerCompression::Lz4: return "lz4";

            default: return "none";
        }
    }

    bool isCompressionSupported(const LayerCompression compression)
    {
        return compression == LayerCompression::None || compression == LayerCompression::Gzip ||
               compression == LayerCompression::Zstd;
    }

    LayerByteStream::LayerByteStream(IByteStream& source)
        : m_source {source}
        , m_inflate {nullptr, destroyInflateStream}
        , m_zstd {nullptr, destroyZstdStream}
    {
    }

    LayerByteStream::~LayerByteStream() = default;

    LayerCompression LayerByteStream::compression()
    {
        if (!m_started)
        {
            start();
        }

        return m_compression;
    }

    void LayerByteStream::start()
    {
        m_started = true;

        std::array<char, SIGNATURE_SIZE> signature {};
        const auto got {readExact(m_source, signature.data(), signature.size())};

        m_pending.assign(signature.data(), got);
        m_compression = detectCompression(m_pending);

        if (m_compression == LayerCompression::None)
        {
            // No signature matched: the bytes already read are handed back untouched and
            // the rest of the stream is passed straight through, as a plain tar.
            return;
        }

        if (!isCompressionSupported(m_compression))
        {
            // Recognized, and not something this reader can decompress. Reporting end of
            // stream keeps the compressed bytes from being read as tar data; the caller
            // asks compression() to find out why the layer was empty.
            m_pending.clear();
            m_finished = true;
            return;
        }

        if (m_compression == LayerCompression::Gzip)
        {
            auto stream {std::make_unique<z_stream>()};
            *stream = z_stream {};

            if (inflateInit2(stream.get(), GZIP_WINDOW_BITS) != Z_OK)
            {
                // Inflation could not be set up: report end of stream rather than returning
                // the compressed bytes as if they were tar data.
                m_pending.clear();
                m_finished = true;
                return;
            }

            m_inflate.reset(stream.release());
        }
        else
        {
            auto* stream {ZSTD_createDStream()};

            if (stream == nullptr || ZSTD_isError(ZSTD_initDStream(stream)))
            {
                destroyZstdStream(stream);
                m_pending.clear();
                m_finished = true;
                return;
            }

            m_zstd.reset(stream);
        }

        m_input.resize(BUFFER_SIZE);

        // The signature bytes belong to the compressed stream, so they are fed back to
        // the decompressor instead of to the caller.
        std::copy_n(m_pending.data(), m_pending.size(), m_input.data());
        m_inputSize = m_pending.size();
        m_inputOffset = 0;
        m_pending.clear();
    }

    std::size_t LayerByteStream::drainPending(char* buffer, std::size_t size)
    {
        const auto available {m_pending.size() - m_pendingOffset};
        const auto count {std::min(available, size)};

        std::copy_n(m_pending.data() + m_pendingOffset, count, buffer);
        m_pendingOffset += count;

        if (m_pendingOffset == m_pending.size())
        {
            m_pending.clear();
            m_pendingOffset = 0;
        }

        return count;
    }

    bool LayerByteStream::refill()
    {
        m_inputSize = m_source.read(m_input.data(), m_input.size());
        m_inputOffset = 0;
        return m_inputSize > 0;
    }

    std::size_t LayerByteStream::read(char* buffer, std::size_t size)
    {
        if (size == 0)
        {
            return 0;
        }

        if (!m_started)
        {
            start();
        }

        if (!m_pending.empty())
        {
            return drainPending(buffer, size);
        }

        if (m_compression == LayerCompression::None)
        {
            return m_finished ? 0 : m_source.read(buffer, size);
        }

        if (m_finished)
        {
            return 0;
        }

        return m_compression == LayerCompression::Gzip ? readInflate(buffer, size) : readZstd(buffer, size);
    }

    std::size_t LayerByteStream::readInflate(char* buffer, std::size_t size)
    {
        auto* stream {static_cast<z_stream*>(m_inflate.get())};
        stream->next_out = reinterpret_cast<Bytef*>(buffer);
        stream->avail_out = static_cast<uInt>(size);

        while (stream->avail_out == size)
        {
            if (m_inputOffset == m_inputSize && !refill())
            {
                // Input ran out before the stream ended: a truncated blob. Reporting end
                // of stream lets the caller treat it as malformed input.
                m_finished = true;
                break;
            }

            stream->next_in = reinterpret_cast<Bytef*>(m_input.data() + m_inputOffset);
            stream->avail_in = static_cast<uInt>(m_inputSize - m_inputOffset);

            const auto result {inflate(stream, Z_NO_FLUSH)};

            m_inputOffset = m_inputSize - stream->avail_in;

            if (result == Z_STREAM_END)
            {
                // A layer blob is a single gzip member; anything after it is ignored.
                m_finished = true;
                break;
            }

            if (result != Z_OK && result != Z_BUF_ERROR)
            {
                m_finished = true;
                break;
            }
        }

        return size - stream->avail_out;
    }

    std::size_t LayerByteStream::readZstd(char* buffer, std::size_t size)
    {
        auto* stream {static_cast<ZSTD_DStream*>(m_zstd.get())};
        ZSTD_outBuffer output {buffer, size, 0};

        while (output.pos == 0)
        {
            if (m_inputOffset == m_inputSize && !refill())
            {
                // Input ran out mid-frame: same treatment as a truncated gzip member.
                m_finished = true;
                break;
            }

            ZSTD_inBuffer input {m_input.data(), m_inputSize, m_inputOffset};
            const auto result {ZSTD_decompressStream(stream, &output, &input)};

            m_inputOffset = input.pos;

            if (ZSTD_isError(result))
            {
                m_finished = true;
                break;
            }

            if (result == 0)
            {
                // Frame complete. A layer blob is a single frame; anything after it is
                // ignored, which is how the gzip path treats trailing bytes too.
                m_finished = true;
                break;
            }
        }

        return output.pos;
    }
} // namespace containerimages
