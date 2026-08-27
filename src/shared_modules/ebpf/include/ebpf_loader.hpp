/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "ebpf_types.hpp"
#include <string>
#include <vector>

struct bpf_object;
struct bpf_link;
struct bpf_program;
struct ring_buffer;

namespace wazuh::ebpf {

/**
 * @brief RAII owner of one BPF object: loads the bytecode, attaches only the
 * hooks of the requested event class and reads its own ring buffer.
 *
 * Every module that wants kernel telemetry links this library and owns an
 * instance. There is no shared engine, no subscription registry and no dispatch
 * thread: the module polls from its own thread.
 *
 * The methods are virtual so consumer tests can inject MockEbpfLoader; there is
 * a single production implementation.
 */
class EbpfLoader {
public:
    EbpfLoader() = default;
    virtual ~EbpfLoader();

    EbpfLoader(const EbpfLoader&) = delete;
    EbpfLoader& operator=(const EbpfLoader&) = delete;

    /**
     * @brief True if the running kernel is 5.8 or newer (CO-RE + ring buffer).
     */
    static bool isKernelSupported();

    /**
     * @brief True if BPF LSM is enabled in /sys/kernel/security/lsm.
     */
    static bool isBpfLsmActive();

    /**
     * @brief Loads and attaches the hooks of @p event_class.
     * @param event_class Class of hooks to autoload; the rest stay unloaded.
     * @param bpf_obj_path Path to the precompiled object. Empty uses the default.
     */
    virtual bool load(EventClass event_class, const std::string& bpf_obj_path = "");

    /**
     * @brief Consumes pending ring buffer records, invoking @p callback per event.
     * @param callback Invoked synchronously on the calling thread.
     * @param timeout_ms Poll timeout; returns after it expires with no records.
     * @return false on ring buffer error.
     *
     * FILE is the only class the object implements, so records decode straight
     * to FileEvent. When exec/network hooks land, tag the kernel record with its
     * class and switch on it here.
     */
    virtual bool poll(const FileEventCallback& callback, int timeout_ms = 250);

    /**
     * @brief Detaches every program and closes the object.
     */
    virtual void close();

    virtual bool isLsmActive() const noexcept { return m_lsm_active; }
    bool isLoaded() const noexcept { return m_bpf_obj != nullptr; }

private:
    bool openAndLoad(const std::string& bpf_obj_path);
    void selectPrograms(bool prefer_dpath);
    bool attach();
    static int onRingSample(void* ctx, void* data, size_t size);

    struct bpf_object* m_bpf_obj{nullptr};
    struct ring_buffer* m_ring_buf{nullptr};
    std::vector<struct bpf_link*> m_links;
    const FileEventCallback* m_callback{nullptr};
    bool m_lsm_active{false};
};

} // namespace wazuh::ebpf
