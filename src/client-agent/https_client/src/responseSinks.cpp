/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "responseSinks.hpp"

size_t writeToBodySink(char* data, size_t size, size_t nmemb, void* userData)
{
    auto* sink = static_cast<BodySink*>(userData);
    const size_t total = size * nmemb;

    // Enforce the cap here rather than after the fact: a consumer that only checks the
    // finished body has already let a hostile or faulty manager decide how much of this
    // agent's memory to take, on a schedule the manager controls. A short count aborts the
    // transfer, exactly as it does for the file sink. (body->size() <= max always, so the
    // subtraction cannot underflow.)
    if (sink->max != 0 && total > sink->max - sink->body->size())
    {
        return 0;
    }

    try
    {
        sink->body->append(data, total);
    }
    catch (...)
    {
        return 0; // LCOV_EXCL_LINE: allocation failure aborts the transfer.
    }

    return total;
}

size_t writeToFileSink(char* data, size_t size, size_t nmemb, void* userData)
{
    auto* sink = static_cast<FileSink*>(userData);
    const size_t total = size * nmemb;

    // Enforce the cap: a short count aborts the transfer, so a hostile or
    // faulty manager cannot fill the agent's disk. (written <= max always,
    // so max - written never underflows.)
    if (sink->max != 0 && total > sink->max - sink->written)
    {
        return 0;
    }

    // A short fwrite (write error / disk full) also aborts.
    const size_t wrote = std::fwrite(data, 1, total, sink->file);
    sink->written += wrote;
    return wrote;
}
