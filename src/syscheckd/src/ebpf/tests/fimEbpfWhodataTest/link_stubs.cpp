/*
 * Link-time stubs for symbols fimebpf.so needs from container_baseline_fim
 * dot cpp, container_baseline_fim_bridge dot c, and container_live_fim dot
 * cpp (the "syscheck" global and the fim_db_transaction family plus
 * validate_and_persist_fim_event those files call), which none of THESE
 * tests (ebpf_whodata.cpp's own logic) actually exercise.
 *
 * Without these, a minimal test binary would have to link the full
 * syscheckd_lib, fimdb, and agent_sync_protocol dependency chain just to
 * satisfy the linker. That chain turned out to be a genuine circular CMake
 * target dependency (syscheckd_lib depends on fimebpf, which transitively
 * depends back on wazuh_modulesd_lib and syscollector, which depend back on
 * fimebpf again), which CMake's own link-group cycle validation refuses to
 * build. Providing narrow stubs for exactly the symbols this library's
 * non-exercised code paths need sidesteps that fight entirely, since this
 * test suite has no reason to link the real implementations anyway.
 *
 * Both headers below (syscheck.h for validate_and_persist_fim_event, db.h
 * for the fim_db_transaction family) already declare their C functions
 * inside extern "C" guards, so plain definitions here pick up correct C
 * linkage automatically without repeating it.
 */

#include "syscheck.h"
#include "db.h"
#include "agent_sync_protocol_c_interface.h"

syscheck_config syscheck = {};

// persist_syscheck_msg.c (also built into fimebpf.so) calls this directly.
void asp_persist_diff(AgentSyncProtocolHandle*, const char*, Operation_t, const char*, const char*, uint64_t) {}

bool validate_and_persist_fim_event(
    const cJSON*, const char*, Operation_t, const char*, uint64_t, const char*, bool, OSList*, void*, int)
{
    return true;
}

TXN_HANDLE fim_db_transaction_start(const char*, result_callback_t, void*)
{
    return nullptr;
}

FIMDBErrorCode fim_db_transaction_sync_row_json(TXN_HANDLE, const char*, const char*)
{
    return FIMDB_OK;
}

FIMDBErrorCode fim_db_transaction_deleted_rows(TXN_HANDLE, result_callback_t, void*)
{
    return FIMDB_OK;
}

cJSON* fim_db_get_every_element(const char*, const char*)
{
    return nullptr;
}

FIMDBErrorCode fim_db_container_file_delete(const char*, const char*)
{
    return FIMDB_OK;
}
