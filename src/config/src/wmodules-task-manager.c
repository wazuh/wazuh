/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wmodules.h"
#include "config.h"
#include "global-config.h"
#include "mconf-config.h"
#include "remote-config.h" // the `remoted` struct and REMOTED_HTTPS_VERIFY_*, for the upgrade gates

static const char *XML_TASK_TTL = "task_ttl";
static const char *XML_CLEANUP_INTERVAL = "cleanup_interval";
static const char *XML_MAX_PAYLOAD_BYTES = "max_payload_bytes";
static const char *XML_MAX_TASKS_PER_POLL = "max_tasks_per_poll";

/* Agent upgrade. This module serves remote agent upgrades, so it owns their configuration; the
 * agent-upgrade module is agent-only and configures only what an agent accepts. */
static const char *XML_UPGRADE_ENABLED = "upgrade_enabled";
static const char *XML_WPK_REPOSITORY = "wpk_repository";

/**
 * @brief Resolve every internal option.
 *
 * These come from internal_options.conf, not from the effective document, so they are readable at
 * this point -- wm_config() initialises the default modules before it loads the document.
 *
 * Called from wm_task_manager_read(), which runs inside wm_config() -- BEFORE modulesd daemonizes.
 * That placement is the point: getDefine_Int_default() range-checks each value, so an out-of-range
 * one fails `wazuh-modulesd -t` instead of aborting a module thread after the daemon has already
 * detached from its terminal.
 *
 * getDefine_Int_default() and never bare getDefine_Int(): the latter calls merror_exit() on a
 * missing key, and none of these options ships in a file -- the manager reads only the overrides
 * file, so an option nobody has written is expected to be absent.
 *
 * Every value is passed through to the module as-is: the module resolves the "no opinion" sentinel
 * against its own defaults. Deciding defaults here as well would put them in two places, and they
 * would drift.
 *
 * TWO SENTINELS, AND WHICH ONE A KEY USES IS DECIDED BY ITS DOMAIN.
 *
 * Most of these options start at one, so a `default_val` of 0 is unambiguous "absent" and the
 * module's `<= 0` rule resolves it. Six of them have a MEANINGFUL zero -- "log no agent by name",
 * "cache nothing", "no admission bound", "keep no rotated logs", "never rotate by size" -- and for
 * those a plain 0 would be indistinguishable from the operator asking for exactly that, so the
 * module would hand back the default they were trying to switch off. Those six go through
 * wm_task_manager_zeroable(), which encodes the three states the ABI defines for them.
 */

/**
 * @brief Read an option whose ZERO is a real setting rather than an absence.
 *
 * Three states have to survive one int, and task_manager.h fixes the encoding: 0 means "no
 * opinion", -1 means "the operator asked for zero", and anything positive is the value. This
 * function is the only place the mapping happens.
 *
 * The direction matters. It would be simpler to pass -1 for "absent" and let 0 mean itself, but
 * then a zero-initialised task_manager_config_t -- which is what every embedder produces, the
 * testtool included -- would read as "log rotation off, every admission bound removed". Absence has
 * to be the zero.
 *
 * Reading with a -1 fallback is safe because getDefine_Int_default() returns `default_val` VERBATIM
 * when the key is absent and range-checks only a value it actually read from a file, so -1 never
 * has to satisfy `min`.
 *
 * @return 0 when unset, -1 when explicitly zero, otherwise the configured value.
 */
static int wm_task_manager_zeroable(const char *key, int min, int max) {
    const int value = getDefine_Int_default("wazuh_modules", key, min, max, -1);

    if (value < 0) {
        return 0;  /* Absent: the module applies its own default. */
    }

    return value == 0 ? -1 : value;
}

static void wm_task_manager_read_tunables(wm_task_manager *data) {
    /* Queue mechanics. */
    data->max_attempts = getDefine_Int_default("wazuh_modules", "manager_task_max_attempts", 1, 1000, 0);
    data->max_defer = getDefine_Int_default("wazuh_modules", "manager_task_max_defer", 1, 10000, 0);
    data->backoff_base = getDefine_Int_default("wazuh_modules", "manager_task_backoff_base", 1, 3600, 0);
    data->backoff_cap = getDefine_Int_default("wazuh_modules", "manager_task_backoff_cap", 1, 86400, 0);
    data->defer_base = getDefine_Int_default("wazuh_modules", "manager_task_defer_base", 1, 3600, 0);

    /* Formerly manager_task_poll_interval, when this was the period of a polling loop. The
     * scheduler now sleeps until the exact instant the earliest backed-off row becomes eligible,
     * so the value is a CEILING on that sleep rather than the mechanism. The key is kept for
     * continuity with deployments that already set it. */
    data->wake_backstop = getDefine_Int_default("wazuh_modules", "manager_task_poll_interval", 1, 3600, 0);

    data->sweep_interval = getDefine_Int_default("wazuh_modules", "manager_task_sweep_interval", 1, 3600, 0);
    data->claim_grace = getDefine_Int_default("wazuh_modules", "manager_task_claim_grace", 1, 3600, 0);
    data->wdb_timeout = getDefine_Int_default("wazuh_modules", "manager_task_wdb_timeout", 1, 600, 0);

    /* Per-type bounds. */
    data->vd_scan_timeout = getDefine_Int_default("wazuh_modules", "manager_task_vd_scan_timeout", 1, 3600, 0);
    data->delete_timeout = getDefine_Int_default("wazuh_modules", "manager_task_delete_timeout", 1, 7200, 0);
    data->max_pending_deletes = wm_task_manager_zeroable("manager_task_max_pending_deletes", 0, 1000000);
    data->max_pending_scans = wm_task_manager_zeroable("manager_task_max_pending_scans", 0, 1000000);

    /* Retention. */
    data->retention_days = getDefine_Int_default("wazuh_modules", "manager_task_retention_days", 1, 3650, 0);
    data->dead_letter_retention_days = getDefine_Int_default("wazuh_modules", "manager_task_dead_letter_retention_days", 1, 3650, 0);
    data->history_per_schedule = getDefine_Int_default("wazuh_modules", "manager_task_history_per_schedule", 1, 100000, 0);
    data->max_rows = getDefine_Int_default("wazuh_modules", "manager_task_max_rows", 1, 100000000, 0);

    /* Recurring work. These carried `monitord.*` names while log rotation and agent monitoring
     * belonged to wazuh-manager-monitord, and they are RENAMED here rather than aliased.
     *
     * That is a deliberate break, and it is silent: _read_file() splits each line at the first '.'
     * and compares BOTH halves, so `monitord.rotate_log` does not answer a lookup for
     * `wazuh_modules.manager_task_log_rotate` -- it is simply never read. An operator who set any of
     * these on an earlier build has to rename the key, which is why the rename is called out in
     * docs/ref/modules/task_manager/configuration.md rather than only living here. The AGENT keeps
     * its `monitord.*` keys for its own rotation; only the manager's moved. */
    data->delete_old_agents = getDefine_Int_default("wazuh_modules", "manager_task_delete_old_agents", 0, 9600, 0);
    data->monitor_agents = getDefine_Int_default("wazuh_modules", "manager_task_monitor_agents", 0, 1, 1);
    data->disconnect_log_max = wm_task_manager_zeroable("manager_task_disconnect_log_max", 0, 1000000);
    data->rotate_log = getDefine_Int_default("wazuh_modules", "manager_task_log_rotate", 0, 1, 1);
    data->compress = getDefine_Int_default("wazuh_modules", "manager_task_log_compress", 0, 1, 1);
    data->keep_log_days = wm_task_manager_zeroable("manager_task_log_keep_days", 0, 500);
    data->size_rotate_mb = wm_task_manager_zeroable("manager_task_log_size_rotate", 0, 4096);
    data->daily_rotations = getDefine_Int_default("wazuh_modules", "manager_task_log_daily_rotations", 1, 256, 0);
    data->day_wait = getDefine_Int_default("wazuh_modules", "manager_task_log_day_wait", 0, 600, 0);
    data->delete_old_batch = getDefine_Int_default("wazuh_modules", "manager_task_delete_old_batch", 1, 100000, 0);
    data->delete_old_budget = getDefine_Int_default("wazuh_modules", "manager_task_delete_old_budget", 1, 3600, 0);

    /* Threading. */
    data->io_threads = getDefine_Int_default("wazuh_modules", "manager_task_io_threads", 1, 64, 0);
    data->executor_threads = getDefine_Int_default("wazuh_modules", "manager_task_executor_threads", 1, 64, 0);

    /* Agent upgrade.
     *
     * upgrade_workers bounds concurrent BATCHES, not agents: per-agent work is one wazuh-db call on
     * a mutex-guarded socket plus pure CPU, so running agents in parallel would multiply contention
     * on that mutex to buy nothing. The ceiling is deliberately low for a second reason too -- the
     * WPK client is shared_modules/http-request, which caches curl handlers in a process-wide queue
     * of five shared with vulnerability_scanner and indexer_connector, and a large pool here would
     * evict theirs. Note that what bounds TRANSFERS is upgrade_max_concurrent_downloads, not this.
     *
     * upgrade_batch_deadline MUST expire before the Server API's own timeout, which must in turn be
     * shorter than the transport's per-route backstop. The module answering first is what keeps a
     * slow repository producing a per-agent envelope rather than a torn-down connection. */
    data->upgrade_workers = getDefine_Int_default("wazuh_modules", "upgrade_workers", 1, 16, 0);
    data->upgrade_queue_depth = getDefine_Int_default("wazuh_modules", "upgrade_queue_depth", 1, 1000, 0);
    data->upgrade_batch_deadline = getDefine_Int_default("wazuh_modules", "upgrade_batch_deadline", 10, 3600, 0);
    data->upgrade_max_agents = getDefine_Int_default("wazuh_modules", "upgrade_max_agents", 1, 100000, 0);
    data->upgrade_download_attempts = getDefine_Int_default("wazuh_modules", "upgrade_download_attempts", 1, 10, 0);
    data->upgrade_download_timeout = getDefine_Int_default("wazuh_modules", "upgrade_download_timeout", 1000, 600000, 0);
    data->upgrade_max_concurrent_downloads = getDefine_Int_default("wazuh_modules", "upgrade_max_concurrent_downloads", 1, 32, 0);
    data->upgrade_versions_ttl = wm_task_manager_zeroable("upgrade_versions_ttl", 0, 86400);
}

/* Default instance of the module (default_modules[] in wmodules.c): the configuration itself comes from
 * etc/wazuh-manager.conf through wm_task_manager_read_json(). `nodes` is unused (manager only). */
int wm_task_manager_read(__attribute__((unused)) const OS_XML *xml, __attribute__((unused)) xml_node **nodes, wmodule *module) {
    wm_task_manager* data;

    if (!module->data) {
        os_calloc(1, sizeof(wm_task_manager), data);
        data->enabled = 1;
        /* Upgrades are on by default */
        data->upgrade_enabled = 1;
        // Every integer stays 0 here: 0 is the "use the module's default" sentinel.
        module->context = &WM_TASK_MANAGER_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = data;

        wm_task_manager_read_tunables(data);
    }

    return 0;
}

/**
 * @brief `agents_disconnection_time` from the effective `global` section.
 *
 * That value is the disconnection sweep's WINDOW -- the sweep polls it on a shorter interval
 * derived from it -- and remoted reads the same one, which is why `global` had to survive
 * monitord's removal. Read here rather than inside the module so the module needs no configuration
 * reader of its own.
 *
 * NOT in wm_task_manager_read(): wm_config() initialises the default modules BEFORE it calls
 * w_mconf_load(), so there is no effective document to read at that point. This function runs from
 * the section dispatch, which is after it.
 *
 * A read failure returns 0, the "no opinion" sentinel, and the module applies its own default. A
 * warning rather than a fatal error: inside modulesd, exiting here would take every other module
 * down over one `global` problem.
 *
 * @return Seconds, or 0 to leave the choice to the module.
 */
static int wm_task_manager_disconnection_time(void) {
    _Config global_config;
    cJSON *section = w_mconf_section("global");

    memset(&global_config, 0, sizeof(global_config));

    if (section == NULL || Read_Global_JSON(section, &global_config) < 0) {
        mwarn("Cannot read the global configuration; the agent disconnection sweep will use its "
              "default window.");
        cJSON_Delete(section);
        return 0;
    }

    cJSON_Delete(section);

    /* Read_Global_JSON rejects anything below 1 and leaves the struct untouched, so a zero here
     * means the key was absent -- which is the same sentinel. */
    return global_config.agents_disconnection_time > 0 ? (int)global_config.agents_disconnection_time : 0;
}

/**
 * @brief remoted's `legacy` and `https.verification_mode`, which decide whether an upgrade can
 *        actually be DELIVERED once it is created.
 *
 * Read ONCE, here, rather than per request: the alternative is doing it once per agent in a batch
 * that may hold five hundred. The consequence is real -- an operator who edits `remote` needs
 * modulesd restarted, not just remoted, before upgrades see the change.
 *
 * Like the `global` read above, this cannot live in wm_task_manager_read(): there is no effective
 * document until w_mconf_load(), which wm_config() calls afterwards.
 *
 * On failure the validity flag stays 0 and the module fails the delivery gates OPEN. A `remote`
 * problem is remoted's to report; blocking every upgrade on it would turn one daemon's
 * configuration error into a fleet-wide outage of an unrelated feature.
 */
static void wm_task_manager_read_remoted(wm_task_manager *data) {
    remoted remoted_config;
    cJSON *section = w_mconf_section("remote");

    data->remoted_config_read = 0;
    data->remoted_legacy_enabled = 0;
    data->remoted_verification_mode = REMOTED_HTTPS_VERIFY_UNSET;

    memset(&remoted_config, 0, sizeof(remoted_config));
    remoted_config.https.verification_mode = REMOTED_HTTPS_VERIFY_UNSET;

    if (section != NULL && Read_Remote_JSON(section, &remoted_config) >= 0) {
        data->remoted_config_read = 1;
        data->remoted_legacy_enabled = remoted_config.legacy_enabled ? 1 : 0;
        data->remoted_verification_mode = remoted_config.https.verification_mode;
    } else {
        mwarn("Cannot read the remote configuration; the agent upgrade delivery checks will be "
              "skipped.");
    }

    cJSON_Delete(section);

    /* The seven fields Read_Remote_JSON() can allocate. Everything else in the struct is scalar. */
    os_free(remoted_config.lip);
    os_free(remoted_config.https.bind_addr);
    os_free(remoted_config.https.global_prefix);
    os_free(remoted_config.https.certificate);
    os_free(remoted_config.https.key);
    os_free(remoted_config.https.ca);
    os_free(remoted_config.https.ciphers);
}

/* Reader of the `task-manager` section of the effective document (etc/wazuh-manager.conf, see
 * mconf-config.h). `module` is the instance default_modules[] already initialised through
 * wm_task_manager_read(NULL, NULL, module). The schema guarantees non-negative integers; 0 keeps the
 * module default, as with the XML reader. */
int wm_task_manager_read_json(const cJSON *section, wmodule *module) {
    if (module == NULL || module->data == NULL) {
        return 0;
    }

    wm_task_manager *data = module->data;

    /* Outside the section guard below: `global` and `remote` are different sections, and both are
     * still needed when `task-manager` itself is absent -- the sweep needs its interval, and the
     * upgrade gates need remoted's delivery settings. */
    data->disconnection_time = wm_task_manager_disconnection_time();
    wm_task_manager_read_remoted(data);

    if (section == NULL) {
        return 0;
    }

    data->upgrade_enabled =
        w_mconf_json_bool(cJSON_GetObjectItem(section, XML_UPGRADE_ENABLED), data->upgrade_enabled ? 1 : 0);

    /* No schema default on purpose: left NULL, the module picks the repository from the target
     * agent version (upgrade/repoLayout.cpp). */
    const cJSON *repository = cJSON_GetObjectItem(section, XML_WPK_REPOSITORY);

    if (cJSON_IsString(repository) && repository->valuestring[0] != '\0') {
        os_free(data->wpk_repository);
        os_strdup(repository->valuestring, data->wpk_repository);
    }

    const struct {
        const char *key;
        int *value;
    } settings[] = {
        { XML_TASK_TTL, &data->task_ttl },
        { XML_CLEANUP_INTERVAL, &data->cleanup_interval },
        { XML_MAX_PAYLOAD_BYTES, &data->max_payload_bytes },
        { XML_MAX_TASKS_PER_POLL, &data->max_tasks_per_poll },
    };

    for (size_t i = 0; i < sizeof(settings) / sizeof(settings[0]); i++) {
        const cJSON *item = cJSON_GetObjectItem(section, settings[i].key);

        if (cJSON_IsNumber(item) && item->valueint >= 0) {
            *settings[i].value = item->valueint;
        }
    }

    return 0;
}
