#include "agent_metadata_db.h"
#include "../wazuh_db/helpers/wdb_global_helpers.h"
#include "remoted.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Global state previously in secure.c, moved here */
static OSHash *agent_meta_map = NULL;
static pthread_rwlock_t agent_meta_lock;

void agent_metadata_init(void) {
    agent_meta_map = OSHash_Create();
    if (!agent_meta_map) merror_exit("agent_meta_map create failed");
    if (!OSHash_setSize(agent_meta_map, 2048))
        merror_exit("agent_meta_map set size failed");
    pthread_rwlock_init(&agent_meta_lock, NULL);
}

void agent_metadata_teardown(void) {
    if (!agent_meta_map) return;
    /* Optionally iterate and free entries… */
    OSHash_Free(agent_meta_map);
    agent_meta_map = NULL;
    pthread_rwlock_destroy(&agent_meta_lock);
}

void agent_meta_clear(agent_meta_t *m) {
    if (!m) return;
    os_free(m->agent_name);
    os_free(m->agent_version);
    os_free(m->os_name);
    os_free(m->os_version);
    os_free(m->os_platform);
    os_free(m->os_type);
    os_free(m->arch);
    os_free(m->hostname);

    // Free groups array
    if (m->groups) {
        for (size_t i = 0; i < m->groups_count; i++) {
            os_free(m->groups[i]);
        }
        os_free(m->groups);
    }

    memset(m, 0, sizeof(*m));
}

void agent_meta_free(agent_meta_t *m) {
    if (!m) return;
    agent_meta_clear(m);
    os_free(m);
}

agent_meta_t *agent_meta_from_agent_info(const char *id_str,
                                         const char *agent_name,
                                         const struct agent_info_data *ai)
{
    if (!ai) return NULL;

    agent_meta_t *m;
    os_calloc(1, sizeof(*m), m);

    /* Convert id string to int (falls back to 0 if NULL) */
    m->agent_id = id_str ? atoi(id_str) : 0;

    /* Basic fields */
    if (agent_name)    os_strdup(agent_name,    m->agent_name);
    if (ai->version)   os_strdup(ai->version,   m->agent_version);

    /* OS fields (ai->osd must be fully defined by remoted/manager.h) */
    if (ai->osd) {
        if (ai->osd->os_name)     os_strdup(ai->osd->os_name,     m->os_name);
        if (ai->osd->os_version)  os_strdup(ai->osd->os_version,  m->os_version);
        if (ai->osd->os_platform) os_strdup(ai->osd->os_platform, m->os_platform);
        if (ai->osd->os_type)     os_strdup(ai->osd->os_type,     m->os_type);
        if (ai->osd->os_arch)     os_strdup(ai->osd->os_arch,     m->arch);
        if (ai->osd->hostname)    os_strdup(ai->osd->hostname,    m->hostname);
    }

    return m;
}

int agent_meta_upsert_locked(const char *agent_id_str, agent_meta_t *fresh) {
    if (!agent_id_str || !fresh) return -1;

    // Set the lastmsg timestamp to current time
    fresh->lastmsg = time(NULL);

    pthread_rwlock_wrlock(&agent_meta_lock);
    agent_meta_t *old = (agent_meta_t*)OSHash_Get(agent_meta_map, agent_id_str);

    int rc = OSHash_Add(agent_meta_map, agent_id_str, fresh);
    if (rc == 1) {
        (void)OSHash_Delete(agent_meta_map, agent_id_str);
        rc = OSHash_Add(agent_meta_map, agent_id_str, fresh);
    }

    pthread_rwlock_unlock(&agent_meta_lock);

    if (old && old != fresh) agent_meta_free(old);

    return (rc == 2) ? 0 : -1;
}

/* Example snapshot getter: copies strings into caller-owned struct */
int agent_meta_snapshot_str(const char *agent_id_str, agent_meta_t *out) {
    if (!agent_id_str || !out) return -1;

    agent_meta_t tmp = {0};  // accumulates here; if something fails, we clear tmp and return

    pthread_rwlock_rdlock(&agent_meta_lock);
    agent_meta_t *m = (agent_meta_t*)OSHash_Get(agent_meta_map, agent_id_str);
    if (!m) {
        pthread_rwlock_unlock(&agent_meta_lock);
        return -1;
    }

    // Duplicate absolutely everything for complete ownership in 'out'
    tmp.agent_id = m->agent_id;
    if (m->agent_name)    { os_strdup(m->agent_name,    tmp.agent_name);    if (!tmp.agent_name)    goto oom_unlock; }
    if (m->agent_version) { os_strdup(m->agent_version, tmp.agent_version); if (!tmp.agent_version) goto oom_unlock; }
    if (m->os_name)       { os_strdup(m->os_name,       tmp.os_name);       if (!tmp.os_name)       goto oom_unlock; }
    if (m->os_version)    { os_strdup(m->os_version,    tmp.os_version);    if (!tmp.os_version)    goto oom_unlock; }
    if (m->os_platform)   { os_strdup(m->os_platform,   tmp.os_platform);   if (!tmp.os_platform)   goto oom_unlock; }
    if (m->os_type)       { os_strdup(m->os_type,       tmp.os_type);       if (!tmp.os_type)       goto oom_unlock; }
    if (m->arch)          { os_strdup(m->arch,          tmp.arch);          if (!tmp.arch)          goto oom_unlock; }
    if (m->hostname)      { os_strdup(m->hostname,      tmp.hostname);      if (!tmp.hostname)      goto oom_unlock; }
    tmp.lastmsg = m->lastmsg;

    // Deep copy groups array
    if (m->groups && m->groups_count > 0) {
        os_calloc(m->groups_count, sizeof(char*), tmp.groups);
        if (!tmp.groups) goto oom_unlock;
        tmp.groups_count = m->groups_count;
        for (size_t i = 0; i < m->groups_count; i++) {
            if (m->groups[i]) {
                os_strdup(m->groups[i], tmp.groups[i]);
                if (!tmp.groups[i]) goto oom_unlock;
            }
        }
    }

    pthread_rwlock_unlock(&agent_meta_lock);

    // Success: move tmp → out (shallow copy of pointers already ours)
    *out = tmp;
    return 0;

oom_unlock:
    pthread_rwlock_unlock(&agent_meta_lock);
    agent_meta_clear(&tmp);   // clean up what has already been duplicated
    return -1;
}

void agent_meta_cleanup_expired(time_t expire_threshold) {
    if (expire_threshold <= 0) return;
    if (!agent_meta_map) return;

    // Acquire write lock once for the entire operation
    pthread_rwlock_wrlock(&agent_meta_lock);

    time_t now = time(NULL);
    size_t deleted_count = 0;
    unsigned int i = 0;
    OSHashNode *node = OSHash_Begin(agent_meta_map, &i);

    while (node) {
        if (node->key && node->data) {
            agent_meta_t *meta = (agent_meta_t *)node->data;

            // Check if this entry has expired
            if (now - meta->lastmsg > expire_threshold) {
                // Copy the agent ID before deleting
                char agent_id_copy[64];
                strncpy(agent_id_copy, (const char *)node->key, sizeof(agent_id_copy) - 1);
                agent_id_copy[sizeof(agent_id_copy) - 1] = '\0';

                // Move to next node before deleting current one
                node = OSHash_Next(agent_meta_map, &i, node);

                // Delete the expired entry
                agent_meta_t *old = (agent_meta_t *)OSHash_Delete(agent_meta_map, agent_id_copy);
                if (old) {
                    mdebug2("Cleaned up expired metadata cache for agent ID '%s'", agent_id_copy);
                    agent_meta_free(old);
                    deleted_count++;
                }
                continue;
            }
        }
        node = OSHash_Next(agent_meta_map, &i, node);
    }

    pthread_rwlock_unlock(&agent_meta_lock);

    if (deleted_count > 0) {
        minfo("Agent metadata cache cleanup: removed %zu expired entries", deleted_count);
    }
}

/* Thread that periodically cleans up expired cache entries */
void* agent_meta_cleanup_thread(void* arg) {
    (void)arg;

    mdebug1("Agent metadata cache cleanup thread started");

    while (1) {
        // Sleep for 60 seconds between cleanup runs
        sleep(60);

        // Perform cleanup using the configured expiration threshold
        agent_meta_cleanup_expired(enrich_cache_expire_time);
    }

    return NULL;
}
