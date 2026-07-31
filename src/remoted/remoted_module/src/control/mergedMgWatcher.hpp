/*
 * Wazuh remoted module - Merged.mg file watcher
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_CONTROL_MERGED_MG_WATCHER_HPP
#define _REMOTED_CONTROL_MERGED_MG_WATCHER_HPP

#include <functional>
#include <memory>
#include <string>

namespace remoted::control
{
    /**
     * Watches every `merged.mg` under sharedGroupsRoot and multiGroupsRoot and
     * invokes the callback with the absolute path of the merged.mg that changed.
     * The watcher also watches the roots themselves so directories created after
     * startup (new groups / new multigroups) are picked up automatically.
     */
    class MergedMgWatcher
    {
    public:
        MergedMgWatcher(const std::string& sharedGroupsRoot,
                        const std::string& multiGroupsRoot,
                        std::function<void(const std::string& mergedMgPath)> onMergedChanged);
        ~MergedMgWatcher();

        void stop();

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::control

#endif // _REMOTED_CONTROL_MERGED_MG_WATCHER_HPP
