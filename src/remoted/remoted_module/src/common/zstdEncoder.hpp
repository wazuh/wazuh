/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_COMMON_ZSTD_ENCODER_HPP
#define _REMOTED_COMMON_ZSTD_ENCODER_HPP

#include <cstddef>
#include <memory>
#include <string_view>

namespace remoted::common
{

    /**
     * @brief Streaming zstd compressor for response bodies, level 3 fixed: the counterpart of
     *        zstdDecode(). One instance produces exactly one frame.
     *
     * Level 3 is the default level the spike measured (about 1.3 GB/s); it is not configurable, so
     * there is no knob to size or test around.
     */
    class ZstdEncoder final
    {
    public:
        /// What one compress() call did.
        struct Step
        {
            std::size_t consumed {0}; ///< Bytes taken from the input.
            std::size_t produced {0}; ///< Bytes written to the output.
            bool finished {false};    ///< The frame is complete and fully flushed; nothing more will be produced.
        };

        /// @throws std::runtime_error if the compression context cannot be created.
        ZstdEncoder();
        ~ZstdEncoder();

        ZstdEncoder(const ZstdEncoder&) = delete;
        ZstdEncoder& operator=(const ZstdEncoder&) = delete;

        /**
         * @brief Memory one transfer holds while compressing: the context's worst case at level 3
         *        plus one input staging buffer of inputSize() bytes.
         *
         * What a caller reserves against its budget before constructing an encoder.
         */
        static std::size_t memoryRequired();

        /// @brief Recommended size of the slices fed to compress().
        static std::size_t inputSize();

        /**
         * @brief Compress as much of @p input as fits in @p output.
         *
         * Neither buffer has to be consumed in full: a caller loops, passing the unconsumed tail of
         * the input again, until it has what it needs. With @p last set the call also finishes the
         * frame, which may take several calls when @p capacity is small; @p input must then be the
         * unconsumed rest and no more data may follow.
         *
         * @param input    Plain bytes (may be empty).
         * @param output   Destination for compressed bytes.
         * @param capacity Size of @p output; must be non-zero.
         * @param last     No more input follows this call.
         * @throws std::runtime_error on a compression failure.
         */
        Step compress(std::string_view input, char* output, std::size_t capacity, bool last);

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::common

#endif // _REMOTED_COMMON_ZSTD_ENCODER_HPP
