#include "agent_metadata_db.h"
#include "../wazuh_db/helpers/wdb_global_helpers.h"

#include <stdlib.h>
#include <string.h>

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
    os_free(m->agent_ip);
    os_free(m->version);
    os_free(m->os_name);
    os_free(m->os_version);
    os_free(m->os_codename);
    os_free(m->os_platform);
    os_free(m->os_build);
    os_free(m->os_kernel);
    os_free(m->arch);
    memset(m, 0, sizeof(*m));
}

void agent_meta_free(agent_meta_t *m) {
    if (!m) return;
    agent_meta_clear(m);
    os_free(m);
}

agent_meta_t *agent_meta_from_agent_info(const char *id_str,
                                         const struct agent_info_data *ai)
{
    if (!ai) return NULL;

    agent_meta_t *m;
    os_calloc(1, sizeof(*m), m);

    /* Convert id string to int (falls back to 0 if NULL) */
    m->agent_id = id_str ? atoi(id_str) : 0;

    /* Basic fields */
    if (ai->version)   os_strdup(ai->version,   m->version);
    if (ai->agent_ip)  os_strdup(ai->agent_ip,  m->agent_ip);

    /* OS fields (ai->osd must be fully defined by remoted/manager.h) */
    if (ai->osd) {
        if (ai->osd->os_name)     os_strdup(ai->osd->os_name,     m->os_name);
        if (ai->osd->os_version)  os_strdup(ai->osd->os_version,  m->os_version);
        if (ai->osd->os_codename) os_strdup(ai->osd->os_codename, m->os_codename);
        if (ai->osd->os_platform) os_strdup(ai->osd->os_platform, m->os_platform);
        if (ai->osd->os_build)    os_strdup(ai->osd->os_build,    m->os_build);
        if (ai->osd->os_uname)    os_strdup(ai->osd->os_uname,    m->os_kernel);
        if (ai->osd->os_arch)     os_strdup(ai->osd->os_arch,     m->arch);
    }

    return m;
}

int agent_meta_upsert_locked(const char *agent_id_str, agent_meta_t *fresh) {
    if (!agent_id_str || !fresh) return -1;
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
    if (m->agent_id)    { m->agent_id = tmp.agent_id; }
    if (m->agent_ip)    { os_strdup(m->agent_ip,    tmp.agent_ip);    if (!tmp.agent_ip)    goto oom_unlock; }
    if (m->version)     { os_strdup(m->version,     tmp.version);     if (!tmp.version)     goto oom_unlock; }
    if (m->os_name)     { os_strdup(m->os_name,     tmp.os_name);     if (!tmp.os_name)     goto oom_unlock; }
    if (m->os_version)  { os_strdup(m->os_version,  tmp.os_version);  if (!tmp.os_version)  goto oom_unlock; }
    if (m->os_codename) { os_strdup(m->os_codename, tmp.os_codename); if (!tmp.os_codename) goto oom_unlock; }
    if (m->os_platform) { os_strdup(m->os_platform, tmp.os_platform); if (!tmp.os_platform) goto oom_unlock; }
    if (m->os_build)    { os_strdup(m->os_build,    tmp.os_build);    if (!tmp.os_build)    goto oom_unlock; }
    if (m->os_kernel)   { os_strdup(m->os_kernel,   tmp.os_kernel);   if (!tmp.os_kernel)   goto oom_unlock; }
    if (m->arch)        { os_strdup(m->arch,        tmp.arch);        if (!tmp.arch)        goto oom_unlock; }

    pthread_rwlock_unlock(&agent_meta_lock);

    // Success: move tmp → out (shallow copy of pointers already ours)
    *out = tmp;
    return 0;

oom_unlock:
    pthread_rwlock_unlock(&agent_meta_lock);
    agent_meta_free(&tmp);   // clean up what has already been duplicated
    return -1;
}
