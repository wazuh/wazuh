/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_FAKE_DOWNLOAD_REPLY_HPP
#define _HC_FAKE_DOWNLOAD_REPLY_HPP

#include <zstd.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>

/// How the fake manager's /download answers a config request it serves (#38514): the shapes
/// PR #40900's manager puts on the wire, and the ways such a reply arrives broken.
enum class DownloadReply
{
    Plain,              ///< A manager without #40900, or with remoted.http_content_encoding_enabled off.
    Zstd,               ///< One level-3 frame, chunked: what #40900 sends when the agent offers zstd.
    ZstdCorrupt,        ///< That frame with a checksum that doesn't match: rejected after its last byte.
    ZstdTruncatedFrame, ///< The first half of the frame, then a clean terminating chunk.
    ZstdUnterminated    ///< The whole frame, but the stream stops before its terminating chunk.
};

/// The /download knobs, grouped like CaBundleOptions rather than as more positional arguments.
struct DownloadOptions
{
    /// Applies only when the request offered zstd; otherwise the body goes plain, as #40900 does.
    DownloadReply reply {DownloadReply::Plain};
};

/// One /download body as it goes on the wire.
struct DownloadBody
{
    std::string bytes;
    bool zstdEncoded {false}; ///< Send Content-Encoding: zstd.
    bool terminated {true};   ///< false: stop the chunked stream before its terminating chunk.
};

namespace fake_download
{
    /// One level-3 frame streamed with ZSTD_e_end, as #40900's encoder does, so the header carries
    /// no content size. withChecksum adds the optional XXH64 trailer, which nothing else here uses.
    inline std::string zstdFrame(const std::string& plain, bool withChecksum)
    {
        const std::unique_ptr<ZSTD_CCtx, size_t (*)(ZSTD_CCtx*)> cctx {ZSTD_createCCtx(), ZSTD_freeCCtx};
        ZSTD_CCtx_setParameter(cctx.get(), ZSTD_c_compressionLevel, 3);
        ZSTD_CCtx_setParameter(cctx.get(), ZSTD_c_checksumFlag, withChecksum ? 1 : 0);
        std::string frame(ZSTD_compressBound(plain.size()), '\0');
        ZSTD_inBuffer in {plain.data(), plain.size(), 0};
        ZSTD_outBuffer out {frame.data(), frame.size(), 0};
        const size_t left = ZSTD_compressStream2(cctx.get(), &out, &in, ZSTD_e_end);
        frame.resize(left == 0 ? out.pos : 0); // The bound always fits a whole frame.
        return frame;
    }

    inline std::string trimmed(const std::string& text)
    {
        const auto begin = text.find_first_not_of(" \t");
        return begin == std::string::npos ? std::string {} :
               text.substr(begin, text.find_last_not_of(" \t") - begin + 1);
    }

    inline bool isZstdCoding(std::string coding)
    {
        coding = trimmed(coding.substr(0, coding.find(';')));
        std::transform(coding.begin(), coding.end(), coding.begin(), [](unsigned char c)
        {
            return static_cast<char>(std::tolower(c));
        });
        return coding == "zstd";
    }
} // namespace fake_download

/// merged.mg-like text of at least minBytes, one <localfile> per line. zstd blocks are 128 KiB, so
/// the size decides how many whole blocks half a frame still holds.
inline std::string mergedConfigText(size_t minBytes)
{
    std::string text = "#merged.mg\n<agent_config>\n";

    for (int line = 0; text.size() < minBytes; line++)
    {
        text += "  <localfile><location>/var/log/app-" + std::to_string(line) + ".log</location></localfile>\n";
    }

    return text + "</agent_config>\n";
}

/// Whether an Accept-Encoding value lists zstd: comma-separated codings, compared case-insensitively.
/// q-values aren't looked at (#40900 reads q=0 as "not offered"); the agent only ever sends a bare "zstd".
inline bool offersZstd(const std::string& acceptEncoding)
{
    for (size_t start = 0; start <= acceptEncoding.size();)
    {
        const size_t comma = std::min(acceptEncoding.find(',', start), acceptEncoding.size());

        if (fake_download::isZstdCoding(acceptEncoding.substr(start, comma - start)))
        {
            return true;
        }

        start = comma + 1;
    }

    return false;
}

/// The body /download sends for `plain`: the reply shape when the request offered zstd, plain otherwise.
inline DownloadBody shapeDownloadBody(const std::string& plain, DownloadReply reply, bool offeredZstd)
{
    if (!offeredZstd || reply == DownloadReply::Plain)
    {
        return DownloadBody {plain};
    }

    DownloadBody body {fake_download::zstdFrame(plain, reply == DownloadReply::ZstdCorrupt), true};

    if (reply == DownloadReply::ZstdCorrupt)
    {
        body.bytes.back() = static_cast<char>(body.bytes.back() ^ 0xFF); // Last byte of the checksum.
    }
    else if (reply == DownloadReply::ZstdTruncatedFrame)
    {
        body.bytes.resize(body.bytes.size() / 2);
    }

    body.terminated = reply != DownloadReply::ZstdUnterminated;
    return body;
}

#endif // _HC_FAKE_DOWNLOAD_REPLY_HPP
