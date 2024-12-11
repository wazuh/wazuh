/*
 * Copyright (C) 2015, Wazuh Inc.
 * April 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FS_XZ_WRAPPER_HPP
#define _FS_XZ_WRAPPER_HPP

#include <stdexcept>
#include <string>

#include <fs/iDataCollector.hpp>
#include <fs/iDataProvider.hpp>

#include "lzma.h"

namespace fs::xz
{
constexpr inline uint32_t PRESET_9_MAX_COMPRESSION {9};
constexpr inline uint32_t DEFAULT_COMPRESSION_PRESET {PRESET_9_MAX_COMPRESSION};
constexpr inline uint32_t DEFAULT_THREAD_COUNT {1};

/**
 * @brief Wrapper for the xz compressor of the lzma library
 *
 * @details This class needs to be given an implementation of the IDataProvider interface that will be used to
 * fetch all the available input data, and it needs an implementation of the IDataCollector that will be used to
 * receive the processed data.
 */
class Wrapper
{
    uint32_t m_threadCount;                ///< Number of worker threads
    lzma_stream m_strm = LZMA_STREAM_INIT; ///< context for the lzma library api
    lzma_mt m_multiThreadOptions {};       ///< lzma options for multi-thread mode

    /**
     * @brief Configure the stream for compression
     *
     * @param preset Compression preset. A value from 0 to 9. Roughly, the higher the value the higher the
     * compression ratio, at the expense of slower times and more memory usage.
     * @param threadCount Number of worker threads. 0 uses all the available threads.
     */
    void setupCompressor(uint32_t preset, uint32_t threadCount)
    {
        m_strm = LZMA_STREAM_INIT;

        if (threadCount == 1)
        {
            const auto ret {lzma_easy_encoder(&m_strm, preset, LZMA_CHECK_CRC64)};
            if (ret != LZMA_OK)
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Error initializing single-thread xz compressor. Error code: "
                                         + std::to_string(ret));
                // LCOV_EXCL_STOP
            }
        }
        else
        {
            m_multiThreadOptions = {};
            // No flags are needed.
            m_multiThreadOptions.flags = 0;
            // Let liblzma determine a sane block size.
            m_multiThreadOptions.block_size = 0;
            // See the documentation of lzma_mt in lzma/container.h
            m_multiThreadOptions.timeout = 0;
            // To use a preset, filters must be set to NULL.
            m_multiThreadOptions.preset = preset;
            m_multiThreadOptions.filters = nullptr;
            // Use CRC64 for integrity checking.
            m_multiThreadOptions.check = LZMA_CHECK_CRC64;

            // Set number of worker threads
            m_multiThreadOptions.threads = threadCount;
            // If the number of worker threads exceeds the max or it is set to 0 then use max threads
            if (auto maxThreads {lzma_cputhreads()};
                m_multiThreadOptions.threads > maxThreads || m_multiThreadOptions.threads == 0)
            {
                m_multiThreadOptions.threads = maxThreads;
            }

            // Initialize the threaded encoder.
            const auto ret {lzma_stream_encoder_mt(&m_strm, &m_multiThreadOptions)};
            if (ret != LZMA_OK)
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Error initializing multi-threaded xz compressor. Error code: "
                                         + std::to_string(ret));
                // LCOV_EXCL_STOP
            }
        }
    }

    /**
     * @brief Configure the stream for decompression
     *
     * @param threadCount Number of worker threads. 0 uses all the available threads.
     */
    void setupDecompressor(uint32_t threadCount)
    {
        m_strm = LZMA_STREAM_INIT;

        if (threadCount == 1)
        {
            const auto ret {lzma_stream_decoder(&m_strm, UINT64_MAX, 0)};
            if (ret != LZMA_OK)
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Error initializing single-thread xz decompressor. Error code: "
                                         + std::to_string(ret));
                // LCOV_EXCL_STOP
            }
        }
        else
        {
            m_multiThreadOptions = {};
            // No flags are needed.
            m_multiThreadOptions.flags = 0;
            // Let liblzma determine a sane block size.
            m_multiThreadOptions.block_size = 0;
            // See the documentation of lzma_mt in lzma/container.h
            m_multiThreadOptions.timeout = 0;
            // Set threading memory
            m_multiThreadOptions.memlimit_threading = lzma_physmem() / 4;
            // Do not limit max memory
            m_multiThreadOptions.memlimit_stop = UINT64_MAX;
            // Set number of worker threads
            m_multiThreadOptions.threads = threadCount;
            // If the number of worker threads exceeds the max or it is set to 0 then use max threads
            if (auto maxThreads {lzma_cputhreads()};
                m_multiThreadOptions.threads > maxThreads || m_multiThreadOptions.threads == 0)
            {
                m_multiThreadOptions.threads = maxThreads;
            }

            // Initialize the threaded decoder.
            const auto ret {lzma_stream_decoder_mt(&m_strm, &m_multiThreadOptions)};
            if (ret != LZMA_OK)
            {
                // LCOV_EXCL_START
                throw std::runtime_error("Error initializing multi-threaded xz decompressor. Error code: "
                                         + std::to_string(ret));
                // LCOV_EXCL_STOP
            }
        }
    }

    /**
     * @brief Does the actual work of compressing/decompressing
     *
     * @param dataProvider Provider of the input data
     * @param dataCollector Collector of the output data
     */
    void process(IDataProvider& dataProvider, IDataCollector& dataCollector)
    {
        auto action {LZMA_RUN};
        lzma_ret ret;

        dataProvider.begin();
        dataCollector.begin();

        dataCollector.setBuffer(&m_strm.next_out, m_strm.avail_out);
        do
        {
            // Fill the input buffer if it is empty.
            if (m_strm.avail_in == 0)
            {
                auto nextBlock {dataProvider.getNextBlock()};
                if (nextBlock.dataLen > 0)
                {
                    m_strm.next_in = nextBlock.data;
                    m_strm.avail_in = nextBlock.dataLen;
                }
                else
                {
                    // No more input data -> finish process
                    action = LZMA_FINISH;
                }
            }

            ret = lzma_code(&m_strm, action);

            // Output buffer is full
            if (m_strm.avail_out == 0)
            {
                // Save data and reset buffer
                dataCollector.dataReady(m_strm.avail_out);
                dataCollector.setBuffer(&m_strm.next_out, m_strm.avail_out);
            }
        } while (ret == LZMA_OK);

        if (ret == LZMA_STREAM_END)
        {
            // Process ended successfully, save remaining output data
            dataCollector.dataReady(m_strm.avail_out);
            dataCollector.finish();
        }
        else
        {
            // LCOV_EXCL_START
            throw std::runtime_error("Error in xz processing. Error code: " + std::to_string(ret));
            // LCOV_EXCL_STOP
        }
    }

public:
    /**
     * @brief Construct a new Xz Wrapper object
     *
     * @param threadCount  Number of worker threads. 0 uses all the available threads.
     */
    explicit Wrapper(uint32_t threadCount = DEFAULT_THREAD_COUNT)
        : m_threadCount(threadCount)
    {
    }

    ~Wrapper()
    {
        // Cleanup the library memory
        lzma_end(&m_strm);
    }

    /**
     * @brief Compress the input data
     *
     * @param dataProvider Provider of the input data
     * @param dataCollector Collector of the compressed output data
     * @param compressionPreset Compression level. A value from 0 to 9. Roughly, the higher the value the higher the
     * compression ratio, at the expense of slower times and more memory usage.
     */
    void compress(IDataProvider& dataProvider, IDataCollector& dataCollector, uint32_t compressionPreset)
    {
        setupCompressor(compressionPreset, m_threadCount);
        process(dataProvider, dataCollector);
    }

    /**
     * @brief Decompress the input data
     *
     * @param dataProvider Provider of the compressed input data
     * @param dataCollector Collector of the decompressed output data
     */
    void decompress(IDataProvider& dataProvider, IDataCollector& dataCollector)
    {
        setupDecompressor(m_threadCount);
        process(dataProvider, dataCollector);
    }
};

} // namespace fs::xz
#endif //_FS_XZ_WRAPPER_HPP
